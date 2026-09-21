import type { AnnouncementConfig } from "../types/config";

export const announcementConfig: AnnouncementConfig = {
	title: "Let's connect",
	content:
		"Interested in reverse engineering, CTFs, or AI-assisted analysis? Say hello.",
	closable: true,
	link: {
		enable: true,
		text: "Get in touch",
		url: "/about/#contact",
		external: false,
	},
};
