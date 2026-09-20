import { LinkPreset, type NavBarConfig } from "../types/config";

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		{ name: "Blog", url: "/archive/", icon: "material-symbols:article" },
		LinkPreset.About,
		{
			name: "GitHub",
			url: "https://github.com/4r12u",
			icon: "fa7-brands:github",
			external: true,
		},
	],
};
