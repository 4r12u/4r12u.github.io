import type { ProfileConfig } from "../types/config";

export const profileConfig: ProfileConfig = {
	avatar: "assets/images/avatar.webp",
	name: "Duc Nguyen",
	bio: "Arisu / AduangDuc · Information Assurance student & reverse engineering CTF player.",
	typewriter: { enable: false, speed: 80 },
	links: [
		{
			name: "GitHub",
			icon: "fa7-brands:github",
			url: "https://github.com/4r12u",
		},
		{
			name: "Email",
			icon: "material-symbols:mail",
			url: "mailto:ducnguyen120906@gmail.com",
		},
		{
			name: "Facebook",
			icon: "fa7-brands:facebook",
			url: "https://www.facebook.com/ducnguyen111/",
		},
		{
			name: "Instagram",
			icon: "fa7-brands:instagram",
			url: "https://www.instagram.com/claude.opus67/",
		},
		{
			name: "X / Twitter",
			icon: "fa7-brands:x-twitter",
			url: "https://x.com/AduangDucc",
		},
		{
			name: "Discord: ducnguyen129",
			icon: "fa7-brands:discord",
			url: "/about/#contact",
		},
	],
};
