// Local watch and reading services.
export interface AnimeItem {
	title: string;
	status: "watching" | "completed" | "planned";
	rating: number;
	cover: string;
	description: string;
	episodes: string;
	year: string;
	genre: string[];
	studio: string;
	link: string;
	progress: number;
	totalEpisodes: number;
	startDate: string;
	endDate: string;
}

const localAnimeList: AnimeItem[] = [
	{
		title: "MangaDex",
		status: "watching",
		rating: 9.5,
		cover: "/assets/anime/lkls.webp",
		description: "A place to discover and read manga from many communities.",
		episodes: "Manga",
		year: "Manga",
		genre: ["Reading", "Manga"],
		studio: "mangadex.org",
		link: "https://mangadex.org/",
		progress: 1,
		totalEpisodes: 1,
		startDate: "2026-09",
		endDate: "",
	},
	{
		title: "Novel Updates",
		status: "planned",
		rating: 9.2,
		cover: "/assets/anime/rynh.webp",
		description:
			"A catalogue for finding translated light novels and web novels.",
		episodes: "Light novel",
		year: "Light novel",
		genre: ["Reading", "Light novel"],
		studio: "novelupdates.com",
		link: "https://www.novelupdates.com/",
		progress: 0,
		totalEpisodes: 1,
		startDate: "2026-09",
		endDate: "",
	},
	{
		title: "AniList",
		status: "completed",
		rating: 9.4,
		cover: "/assets/anime/laxxx.webp",
		description: "A tracker for keeping anime and manga lists organised.",
		episodes: "Anime & manga",
		year: "Anime & manga",
		genre: ["Tracking", "Anime"],
		studio: "anilist.co",
		link: "https://anilist.co/",
		progress: 1,
		totalEpisodes: 1,
		startDate: "2026-09",
		endDate: "",
	},
	{
		title: "Bilibili Anime",
		status: "watching",
		rating: 9.0,
		cover: "/assets/anime/tz1.webp",
		description: "A familiar place for streaming anime and animated series.",
		episodes: "Anime",
		year: "Anime",
		genre: ["Watching", "Anime"],
		studio: "bilibili.com",
		link: "https://www.bilibili.com/anime/",
		progress: 1,
		totalEpisodes: 1,
		startDate: "2026-09",
		endDate: "",
	},
	{
		title: "Crunchyroll",
		status: "planned",
		rating: 8.8,
		cover: "/assets/anime/cmmn.webp",
		description: "A streaming catalogue for seasonal anime and films.",
		episodes: "Anime",
		year: "Anime",
		genre: ["Watching", "Anime"],
		studio: "crunchyroll.com",
		link: "https://www.crunchyroll.com/",
		progress: 0,
		totalEpisodes: 1,
		startDate: "2026-09",
		endDate: "",
	},
];

export default localAnimeList;
