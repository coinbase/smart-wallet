import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { baseSepolia } from "wagmi/chains";

export const config = getDefaultConfig({
  appName: "ZKLogin Demo",
  projectId: "YOUR_PROJECT_ID",
  chains: [baseSepolia],
  ssr: true,
});
