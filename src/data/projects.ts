// Add personal projects here when they are ready to be published.
export interface Project {
	id: string;
	title: string;
	description: string;
	image: string;
	category: "web" | "mobile" | "desktop" | "other";
	techStack: string[];
	status: "completed" | "in-progress" | "planned";
	liveDemo?: string;
	sourceCode?: string;
	visitUrl?: string;
	startDate: string;
	endDate?: string;
	featured?: boolean;
	tags?: string[];
	showImage?: boolean;
}

export const projectsData: Project[] = [];

export const getProjectStats = () => ({
	total: 0,
	byStatus: { completed: 0, inProgress: 0, planned: 0 },
});

export const getProjectsByCategory = (_category?: string) => projectsData;
export const getFeaturedProjects = () => projectsData;
export const getAllTechStack = () => [] as string[];
