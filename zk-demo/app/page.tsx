"use client";

import { useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  decodeAbiParameters,
  encodeFunctionData,
  hexToBytes,
  pad,
  toHex,
  encodeAbiParameters,
  parseAbiParameters,
  isAddressEqual,
} from "viem";
import { sha256 } from "viem/utils";
import { ConnectButton } from "@rainbow-me/rainbowkit";
import {
  useReadContract,
  useWriteContract,
  useBytecode,
  useReadContracts,
  useAccount,
} from "wagmi";
import base64url from "base64url";

import { NETWORK_CONFIG } from "./blockchain/network";
import {
  COINBASE_SMART_WALLET_ABI,
  COINBASE_SMART_WALLET_FACTORY_ABI,
  ZK_LOGIN_ABI,
} from "./blockchain/abi";
import {
  ISS_BUFFER_LENGTH,
  AUD_BUFFER_LENGTH,
  SUB_BUFFER_LENGTH,
} from "./circuit";
import { getJWT, getKeypairs, removeJWT } from "./local-storage";
import { nonceToAddress } from "./utils";

type OAuthState =
  | {
      loading: false;
      jwt: {
        hash: `0x${string}`;
        header: any;
        payload: any;
        signature: string;
        raw: string;
      };
    }
  | {
      loading: true;
    };

type Owner = {
  address: `0x${string}`;
  index: number;
  type: "removed" | "normal" | "ephemeral" | "zklogin";
};

export default function Home() {
  const router = useRouter();

  const [oauthState, setOauthState] = useState<OAuthState>({ loading: true });
  const [userSalt, setUserSalt] = useState<string | undefined>(undefined);
  const [zkAddress, setZkAddress] = useState<`0x${string}` | undefined>(
    undefined
  );
  const [owners, setOwners] = useState<Owner[]>([]);
  const [removingOwnerIndex, setRemovingOwnerIndex] = useState<number | null>(
    null
  );
  const [ephemeralAddress, setEphemeralAddress] = useState<
    `0x${string}` | undefined
  >(undefined);
  const { address: walletAddress } = useAccount();

  const [jwtInfoExpanded, setJwtInfoExpanded] = useState(false);
  const [walletStateExpanded, setWalletStateExpanded] = useState(true);

  const initialOwnerEncoded = walletAddress
    ? encodeAbiParameters(parseAbiParameters("address"), [walletAddress])
    : "0x";

  // Check if smart wallet exists
  const { data: smartWalletAddress, isLoading: isLoadingWalletAddress } =
    useReadContract({
      address: NETWORK_CONFIG.anvil.COINBASE_SMART_WALLET_FACTORY_ADDRESS,
      abi: COINBASE_SMART_WALLET_FACTORY_ABI,
      functionName: "getAddress",
      query: {
        enabled: !oauthState.loading,
      },
      args: [[initialOwnerEncoded], BigInt(0)],
    });

  // Check if the smart wallet is actually deployed by checking its bytecode
  const {
    data: walletBytecode,
    isLoading: isLoadingBytecode,
    refetch: refetchBytecode,
  } = useBytecode({
    address: isLoadingWalletAddress
      ? undefined
      : (smartWalletAddress as `0x${string}`),
  });

  // Determine if the wallet is deployed based on bytecode presence
  const isWalletDeployed = !!walletBytecode && walletBytecode !== "0x";

  // Prepare contract write for deploying a new smart wallet
  const {
    writeContract: writeContractCreateAccount,
    isPending: isWalletDeploymentPending,
    isSuccess: isWalletDeploymentSuccess,
  } = useWriteContract();

  const deployWallet = () => {
    writeContractCreateAccount({
      address: NETWORK_CONFIG.anvil.COINBASE_SMART_WALLET_FACTORY_ADDRESS,
      abi: COINBASE_SMART_WALLET_FACTORY_ABI,
      functionName: "createAccount",
      args: [[initialOwnerEncoded], BigInt(0)],
    });
  };

  // Check if an address is an owner of the smart wallet
  const { data: nextOwnerIndex, isLoading: isLoadingNextOwnerIndex } =
    useReadContract({
      address: smartWalletAddress as `0x${string}`,
      abi: COINBASE_SMART_WALLET_ABI,
      functionName: "nextOwnerIndex",
      query: {
        refetchInterval: 1000,
        enabled: smartWalletAddress != undefined && isWalletDeployed,
      },
    });

  // Get all owners using ownerAtIndex
  const ownerAtIndexQueries = useMemo(() => {
    if (!nextOwnerIndex || !smartWalletAddress || !isWalletDeployed) return [];

    return Array.from({ length: Number(nextOwnerIndex) }, (_, i) => ({
      address: smartWalletAddress as `0x${string}`,
      abi: COINBASE_SMART_WALLET_ABI,
      functionName: "ownerAtIndex",
      args: [BigInt(i)],
    }));
  }, [nextOwnerIndex, smartWalletAddress, isWalletDeployed]);

  const { data: ownerAtIndexResults, isLoading: isLoadingOwnerAtIndices } =
    useReadContracts({
      contracts: ownerAtIndexQueries,
      query: {
        refetchInterval: 1000,
        enabled: ownerAtIndexQueries.length > 0,
      },
    });

  // Check if the wallet has registered its zkAddress
  const { data: registeredZkAddr, isLoading: isLoadingZkAddr } =
    useReadContract({
      address: NETWORK_CONFIG.anvil.ZK_LOGIN_ADDRESS,
      abi: ZK_LOGIN_ABI,
      functionName: "zkAddrs",
      args: [smartWalletAddress as `0x${string}`],
      query: {
        refetchInterval: 1000,
        enabled: smartWalletAddress != undefined && isWalletDeployed,
      },
    });

  // Prepare contract write for linking wallet to Google
  const {
    writeContract: writeContractLinkGoogle,
    isPending: isLinkGooglePending,
  } = useWriteContract();

  const hasGoogleRecovery = useMemo(() => {
    return (
      registeredZkAddr != undefined &&
      registeredZkAddr !=
        "0x0000000000000000000000000000000000000000000000000000000000000000" &&
      owners.find((owner) => owner.type === "zklogin")
    );
  }, [registeredZkAddr, owners]);

  // Prepare contract write for removing an owner
  const {
    writeContract: writeContractRemoveOwner,
    isSuccess: isRemovingOwnerSuccess,
  } = useWriteContract();

  // Call the recoverAccount method on the ZKLogin contract
  const { writeContract: writeContractRecoverAccount } = useWriteContract();

  // Set the oauth state
  useEffect(() => {
    const handle = async () => {
      try {
        // Check for JWT in localStorage
        const storedJWT = getJWT();
        if (!storedJWT) {
          router.push("/sign-in");
          return;
        }

        // Parse the JWT to get the payload
        const [headerBase64, payloadBase64, signatureBase64] =
          storedJWT.split(".");

        // Decode header and payload
        const header = JSON.parse(base64url.decode(headerBase64));
        const payload = JSON.parse(base64url.decode(payloadBase64));

        setOauthState({
          loading: false,
          jwt: {
            hash: sha256(Buffer.from(headerBase64 + "." + payloadBase64)),
            header: header,
            payload: payload,
            signature: signatureBase64,
            raw: storedJWT,
          },
        });

        // Decode the address from the JWT nonce
        const nonceBase64 = payload.nonce;
        if (nonceBase64) {
          const addressFromJWT = nonceToAddress(nonceBase64);
          setEphemeralAddress(addressFromJWT);
        }

        // If everything is valid, set the states
      } catch (err) {
        // Clear JWT on any error
        removeJWT();
        console.error("Error checking authentication:", err);
        router.push("/sign-in");
      }
    };

    handle();
  }, [router]);

  // Compute zkAddress from JWT
  useEffect(() => {
    const handle = async () => {
      if (oauthState.loading) return;

      // Extract JWT claims needed for zkAddress
      const { iss, aud, sub } = oauthState.jwt.payload;

      const issBuff = pad(Buffer.from(JSON.stringify(iss)), {
        size: ISS_BUFFER_LENGTH,
        dir: "right",
      });

      const audBuff = pad(Buffer.from(JSON.stringify(aud)), {
        size: AUD_BUFFER_LENGTH,
        dir: "right",
      });

      const subBuff = pad(Buffer.from(JSON.stringify(sub)), {
        size: SUB_BUFFER_LENGTH,
        dir: "right",
      });

      // Get userSalt from API
      const saltResponse = await fetch("/api/salt", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ iss, aud, sub }),
      });

      if (!saltResponse.ok) {
        throw new Error("Failed to get user salt");
      }

      const { salt: userSalt } = await saltResponse.json();
      setUserSalt(userSalt);

      // Concatenate all buffers
      const userSaltBytes = hexToBytes(userSalt);
      console.log("userSaltBytes", userSaltBytes);
      const concatenated = Uint8Array.from([
        ...issBuff,
        ...audBuff,
        ...subBuff,
        ...userSaltBytes,
      ]);

      console.log("concatenated", concatenated);

      // Compute zkAddress
      const computedZkAddress = sha256(concatenated);
      setZkAddress(computedZkAddress);
    };

    handle();
  }, [oauthState]);

  // Refetch bytecode when deployment is successful
  useEffect(() => {
    if (isWalletDeploymentSuccess) {
      // Wait a short time for the blockchain to update
      const timer = setTimeout(() => {
        refetchBytecode();
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [isWalletDeploymentSuccess, refetchBytecode]);

  // Reset removingOwnerIndex when the owner is actually removed (or failed)
  useEffect(() => {
    setRemovingOwnerIndex(null);
  }, [isRemovingOwnerSuccess]);

  // Update owners when ownerAtIndex results change
  useEffect(() => {
    if (ownerAtIndexResults) {
      const decodedOwners = ownerAtIndexResults.map(
        (result) =>
          decodeAbiParameters(
            parseAbiParameters("address"),
            pad(result.result as `0x${string}`, {
              size: 32,
              dir: "left",
            })
          )[0]
      );

      const keypairs = getKeypairs();

      console.log(decodedOwners);

      setOwners(
        decodedOwners.map((owner, index) => ({
          address: owner,
          index,
          type:
            owner === NETWORK_CONFIG.anvil.ZK_LOGIN_ADDRESS
              ? "zklogin"
              : owner === "0x0000000000000000000000000000000000000000"
              ? "removed"
              : keypairs.find((keypair) =>
                  isAddressEqual(keypair.address, owner)
                )
              ? "ephemeral"
              : "normal",
        }))
      );
    }
  }, [ownerAtIndexResults]);

  // Function to handle logout
  const handleLogout = () => {
    removeJWT();
    router.push("/sign-in");
  };

  const enableGoogleRecovery = () => {
    if (oauthState.loading) return;

    const addOwnerAddressCall = encodeFunctionData({
      abi: COINBASE_SMART_WALLET_ABI,
      functionName: "addOwnerAddress",
      args: [NETWORK_CONFIG.anvil.ZK_LOGIN_ADDRESS],
    });

    const setZkAddrCall = encodeFunctionData({
      abi: ZK_LOGIN_ABI,
      functionName: "setZkAddr",
      args: [zkAddress ?? "0x"],
    });

    writeContractLinkGoogle({
      address: smartWalletAddress as `0x${string}`,
      abi: COINBASE_SMART_WALLET_ABI,
      functionName: "executeBatch",
      args: [
        [
          {
            target: smartWalletAddress as `0x${string}`,
            value: BigInt(0),
            data: addOwnerAddressCall,
          },
          {
            target: NETWORK_CONFIG.anvil.ZK_LOGIN_ADDRESS,
            value: BigInt(0),
            data: setZkAddrCall,
          },
        ],
      ],
    });
  };

  const removeOwner = (index: number) => {
    setRemovingOwnerIndex(index);

    const owner = owners[index];
    const ownerBytes = encodeAbiParameters(parseAbiParameters("address"), [
      owner.address,
    ]);

    // Then call removeOwnerAtIndex with the index and owner bytes
    writeContractRemoveOwner({
      address: smartWalletAddress as `0x${string}`,
      abi: COINBASE_SMART_WALLET_ABI,
      functionName: "removeOwnerAtIndex",
      args: [BigInt(index), ownerBytes],
    });
  };

  const addEphemeralOwner = async () => {
    if (oauthState.loading || !smartWalletAddress || !ephemeralAddress) return;

    const rawJWT = oauthState.jwt.raw;
    const [headerBase64] = rawJWT.split(".");
    const jwtHeaderJson = base64url.decode(headerBase64);

    const newOwner = encodeAbiParameters(parseAbiParameters("address"), [
      ephemeralAddress,
    ]);

    try {
      // Make a request to the GO server's /proof endpoint
      const proofResponse = await fetch("http://localhost:8080/proof", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jwt: rawJWT,
          user_salt: userSalt,
        }),
      });
      if (!proofResponse.ok) {
        throw new Error("Failed to generate proof");
      }

      const { proof } = await proofResponse.json();
      const parsedProof = parseProof(proof);

      // Convert the signature from base64url to hex
      const jwtSignature = toHex(base64url.toBuffer(oauthState.jwt.signature));

      writeContractRecoverAccount({
        address: NETWORK_CONFIG.anvil.ZK_LOGIN_ADDRESS,
        abi: ZK_LOGIN_ABI,
        functionName: "recoverAccount",
        args: [
          smartWalletAddress, // account
          NETWORK_CONFIG.anvil.GOOGLE_IDP_ADDRESS, // idp
          oauthState.jwt.hash, // jwtHash
          jwtHeaderJson, // jwtHeaderJson
          jwtSignature, // jwtSignature
          newOwner, // newOwner
          {
            proof: parsedProof.proof.map(BigInt) as any,
            commitments: parsedProof.commitments.map(BigInt) as any,
            commitmentPok: parsedProof.commitmentPok.map(BigInt) as any,
          }, // proof
        ],
      });
    } catch (error) {
      console.error("Error during recovery:", error);
    }
  };

  const parseProof = (proof: string) => {
    // Convert base64url proof to bytes
    const proofBytes = base64url.toBuffer(proof);

    // Each field element is 32 bytes (256 bits)
    const fpSize = 32;

    // Parse the proof components
    const proofComponents = [];

    // First 8 elements are the proof
    for (let i = 0; i < 8; i++) {
      const start = i * fpSize;
      const end = start + fpSize;
      const element = toHex(Buffer.from(proofBytes.subarray(start, end)));
      proofComponents.push(element);
    }

    // Next 4 bytes contain the commitment count
    const commitmentCountBytes = proofBytes.subarray(
      fpSize * 8,
      fpSize * 8 + 4
    );
    const commitmentCount = new DataView(
      commitmentCountBytes.buffer,
      commitmentCountBytes.byteOffset,
      commitmentCountBytes.byteLength
    ).getUint32(0, false);

    if (commitmentCount !== 1) {
      throw new Error("Invalid commitment count");
    }

    // Parse commitments (2 * commitmentCount elements)
    const commitments = [];
    for (let i = 0; i < 2 * commitmentCount; i++) {
      const start = fpSize * 8 + 4 + i * fpSize;
      const end = start + fpSize;
      const element = toHex(Buffer.from(proofBytes.subarray(start, end)));
      commitments.push(element);
    }

    // Parse commitment POK (2 elements)
    const commitmentPok = [];
    for (let i = 0; i < 2; i++) {
      const start = fpSize * 8 + 4 + 2 * commitmentCount * fpSize + i * fpSize;
      const end = start + fpSize;
      const element = toHex(Buffer.from(proofBytes.subarray(start, end)));
      commitmentPok.push(element);
    }

    return {
      proof: proofComponents,
      commitments,
      commitmentPok,
    };
  };

  if (oauthState.loading) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center p-4 bg-gradient-to-b from-gray-900 to-gray-800 text-white">
        <div className="text-xl">Loading...</div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex flex-col bg-gradient-to-b from-gray-900 to-gray-800 text-white relative">
      {/* ConnectButton in the top right corner */}
      <div className="absolute top-4 right-4 z-10">
        <ConnectButton accountStatus="avatar" showBalance={false} />
      </div>

      {/* Header */}
      <header className="w-full p-4 flex justify-between items-center border-b border-gray-700">
        <div className="flex items-center">
          <h1 className="text-2xl font-bold">ZKLogin Demo</h1>
        </div>
      </header>

      {/* Main content */}
      <div className="flex-1 p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          {/* JWT info - Full width */}
          <div className="bg-gray-800 rounded-xl shadow-lg border border-gray-700 overflow-hidden">
            <div className="w-full p-4 flex justify-between items-center bg-gray-800 hover:bg-gray-700 transition-colors rounded-t-xl">
              <button
                onClick={() => setJwtInfoExpanded(!jwtInfoExpanded)}
                className="flex-1 flex items-center"
              >
                <h2 className="text-xl font-semibold text-left">
                  JWT Information
                </h2>
              </button>
              <div className="flex items-center space-x-4">
                <button
                  onClick={() => router.push("/sign-in")}
                  className="px-3 py-1.5 bg-gray-700 hover:bg-blue-600 text-gray-200 hover:text-white rounded-md font-medium transition-colors text-sm border border-gray-600 hover:border-blue-500"
                >
                  New Ephemeral Key
                </button>
                <button
                  onClick={handleLogout}
                  className="px-3 py-1.5 bg-gray-700 hover:bg-red-600 text-gray-200 hover:text-white rounded-md font-medium transition-colors text-sm border border-gray-600 hover:border-red-500"
                >
                  Sign Out
                </button>
                <button
                  onClick={() => setJwtInfoExpanded(!jwtInfoExpanded)}
                  className="flex items-center"
                >
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    className={`h-5 w-5 transform transition-transform ${
                      jwtInfoExpanded ? "rotate-180" : ""
                    }`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                </button>
              </div>
            </div>
            {jwtInfoExpanded && (
              <div className="p-4 space-y-4">
                <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg overflow-hidden border border-gray-700 shadow-lg">
                  <div className="px-4 py-2 bg-gradient-to-r from-gray-800 to-gray-700 border-b border-gray-700">
                    <h3 className="text-sm font-medium text-blue-300">
                      Header
                    </h3>
                  </div>
                  <div className="p-4 bg-gray-900/50">
                    <pre className="overflow-x-auto">
                      <code className="text-gray-200 font-mono text-sm">
                        {JSON.stringify(oauthState.jwt.header, null, 2)}
                      </code>
                    </pre>
                  </div>
                </div>
                <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg overflow-hidden border border-gray-700 shadow-lg">
                  <div className="px-4 py-2 bg-gradient-to-r from-gray-800 to-gray-700 border-b border-gray-700">
                    <h3 className="text-sm font-medium text-green-300">
                      Payload
                    </h3>
                  </div>
                  <div className="p-4 bg-gray-900/50">
                    <pre className="overflow-x-auto">
                      <code className="text-gray-200 font-mono text-sm">
                        {JSON.stringify(oauthState.jwt.payload, null, 2)}
                      </code>
                    </pre>
                  </div>
                </div>
                <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg overflow-hidden border border-gray-700 shadow-lg">
                  <div className="px-4 py-2 bg-gradient-to-r from-gray-800 to-gray-700 border-b border-gray-700">
                    <h3 className="text-sm font-medium text-purple-300">
                      Signature
                    </h3>
                  </div>
                  <div className="p-4 bg-gray-900/50">
                    <pre className="overflow-x-auto break-all">
                      <code className="text-gray-200 font-mono text-sm">
                        {oauthState.jwt.signature}
                      </code>
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Smart Wallet State box - Full width */}
          <div className="bg-gray-800 rounded-xl shadow-lg border border-gray-700 overflow-hidden">
            <button
              onClick={() => setWalletStateExpanded(!walletStateExpanded)}
              className={`w-full p-4 flex justify-between items-center bg-gray-800 hover:bg-gray-700 transition-colors ${
                walletStateExpanded ? "rounded-t-xl" : "rounded-xl"
              }`}
            >
              <h2 className="text-xl font-semibold">Smart Wallet State</h2>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className={`h-5 w-5 transform transition-transform ${
                  walletStateExpanded ? "rotate-180" : ""
                }`}
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M19 9l-7 7-7-7"
                />
              </svg>
            </button>

            {walletStateExpanded && !oauthState.loading && (
              <div className="p-4 pt-0">
                <div className="space-y-4">
                  {/* ZK Address - Always shown */}
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2">
                      ZK Address
                    </h3>
                    <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg overflow-hidden border border-gray-700 shadow-lg">
                      <div className="p-4 bg-gray-900/50">
                        <pre className="overflow-x-auto break-all">
                          <code className="text-gray-200 font-mono text-sm">
                            {zkAddress || "Not computed yet"}
                          </code>
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Smart Wallet Address or Deploy Button */}
                  <div>
                    <h3 className="text-sm font-medium text-gray-400 mb-2">
                      Smart Wallet
                    </h3>
                    {isLoadingWalletAddress || isLoadingBytecode ? (
                      <p className="text-gray-400">
                        Checking smart wallet status...
                      </p>
                    ) : isWalletDeployed ? (
                      <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-lg overflow-hidden border border-gray-700 shadow-lg">
                        <div className="p-4 bg-gray-900/50">
                          <pre className="overflow-x-auto break-all">
                            <code className="text-gray-200 font-mono text-sm">
                              {smartWalletAddress}
                            </code>
                          </pre>
                        </div>
                      </div>
                    ) : (
                      <div>
                        <button
                          onClick={deployWallet}
                          disabled={isWalletDeploymentPending}
                          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          {isWalletDeploymentPending
                            ? "Deploying..."
                            : "Deploy Smart Wallet"}
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Google Recovery Protection - Only shown if wallet is deployed */}
                  {isWalletDeployed && (
                    <div>
                      <h3 className="text-sm font-medium text-gray-400 mb-2">
                        Google Recovery Protection
                      </h3>
                      {isLoadingZkAddr ? (
                        <p className="text-sm text-gray-400">
                          Checking recovery status...
                        </p>
                      ) : hasGoogleRecovery ? (
                        <div className="flex items-center space-x-4">
                          <button
                            onClick={addEphemeralOwner}
                            className="px-3 py-1.5 bg-orange-700/80 hover:bg-orange-700 text-white rounded-md text-sm"
                          >
                            Add Ephemeral Owner
                          </button>
                          {ephemeralAddress && (
                            <div className="text-sm text-gray-300">
                              <span className="font-medium">
                                Ephemeral Key:
                              </span>{" "}
                              <span className="font-mono">
                                {ephemeralAddress}
                              </span>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div>
                          <button
                            onClick={enableGoogleRecovery}
                            disabled={isLinkGooglePending}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {isLinkGooglePending
                              ? "Enabling..."
                              : "Enable Google Recovery"}
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Owners - Only shown if wallet is deployed */}
                  {isWalletDeployed && (
                    <div>
                      <h3 className="text-sm font-medium text-gray-400 mb-2">
                        Owners
                      </h3>
                      {isLoadingNextOwnerIndex || isLoadingOwnerAtIndices ? (
                        <p className="text-sm text-gray-400">
                          Checking owners...
                        </p>
                      ) : owners.length > 0 ? (
                        <div className="mt-1 space-y-2">
                          {owners.map((owner, index) => (
                            <div
                              key={index}
                              className="flex items-center justify-between p-2 bg-gray-700 rounded-lg"
                            >
                              <div className="flex items-center space-x-2">
                                <p className="text-sm font-mono break-all">
                                  {owner.address}
                                </p>
                                {owner.type === "zklogin" && (
                                  <span className="shrink-0 px-2 py-1 text-xs bg-blue-600/20 text-white rounded-md">
                                    ZKLogin Contract
                                  </span>
                                )}
                                {owner.type === "ephemeral" && (
                                  <span className="shrink-0 px-2 py-1 text-xs bg-purple-600/20 text-white rounded-md">
                                    Ephemeral
                                  </span>
                                )}
                                {owner.type === "removed" && (
                                  <span className="shrink-0 px-2 py-1 text-xs bg-red-600/20 text-white rounded-md">
                                    Removed
                                  </span>
                                )}
                                {owner.type === "normal" && (
                                  <span className="shrink-0 px-2 py-1 text-xs bg-gray-600/80 text-white rounded-md">
                                    Normal
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center space-x-2">
                                {owner.type !== "removed" && (
                                  <button
                                    onClick={() => removeOwner(index)}
                                    className="shrink-0 p-1 text-gray-400 hover:text-red-500 rounded-full hover:bg-gray-600 transition-colors"
                                    title="Remove owner"
                                    disabled={removingOwnerIndex === index}
                                  >
                                    {removingOwnerIndex === index ? (
                                      <svg
                                        className="animate-spin h-5 w-5 text-gray-400"
                                        xmlns="http://www.w3.org/2000/svg"
                                        fill="none"
                                        viewBox="0 0 24 24"
                                      >
                                        <circle
                                          className="opacity-25"
                                          cx="12"
                                          cy="12"
                                          r="10"
                                          stroke="currentColor"
                                          strokeWidth="4"
                                        ></circle>
                                        <path
                                          className="opacity-75"
                                          fill="currentColor"
                                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                                        ></path>
                                      </svg>
                                    ) : (
                                      <svg
                                        xmlns="http://www.w3.org/2000/svg"
                                        className="h-5 w-5"
                                        viewBox="0 0 20 20"
                                        fill="currentColor"
                                      >
                                        <path
                                          fillRule="evenodd"
                                          d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                                          clipRule="evenodd"
                                        />
                                      </svg>
                                    )}
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-sm text-gray-400">No owners found</p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
