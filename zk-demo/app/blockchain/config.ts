import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { anvil } from "wagmi/chains";

export const config = getDefaultConfig({
  appName: "ZKLogin Demo",
  projectId: "YOUR_PROJECT_ID",
  chains: [anvil],
  ssr: true,
});
