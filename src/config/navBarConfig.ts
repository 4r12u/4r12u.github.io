import { LinkPreset, type NavBarConfig } from "../types/config";

export const navBarConfig: NavBarConfig = {
	links: [
		LinkPreset.Home,
		LinkPreset.Archive,
		{
			name: "My",
			url: "/content/",
			icon: "material-symbols:person",
			children: [
				LinkPreset.Anime,
				LinkPreset.Diary,
				LinkPreset.Albums,
				{
					name: "My Devices",
					url: "/devices/",
					icon: "material-symbols:devices",
				},
			],
		},
		LinkPreset.About,
		{
			name: "Others",
			url: "#",
			icon: "material-symbols:more-horiz",
			children: [
				LinkPreset.Projects,
				LinkPreset.Skills,
				LinkPreset.AITools,
				LinkPreset.Timeline,
			],
		},
		{
			name: "GitHub",
			url: "https://github.com/4r12u",
			icon: "fa7-brands:github",
			external: true,
		},
	],
};
