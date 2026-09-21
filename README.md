# Arisu — Duc Nguyen

Personal website and blog for Nguyen Minh Duc (Arisu / AduangDuc), an Information Assurance undergraduate at FPT University, Hanoi campus, and a reverse engineering CTF player with Loi Yeu Kho Noi.

Built with [Mizuki](https://github.com/LyraVoid/Mizuki) and Astro. The original artwork and theme attribution are retained. Site URL: https://4r12u.github.io/.

## Run locally

Use Node.js 24 and the pnpm version declared in package.json.

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

## Personalize

- Profile and social links: src/config/profileConfig.ts
- About, education, interests, and contact: src/content/spec/about.md
- Homepage introduction: src/components/features/home/Introduction.astro
- Site title, banner copy, and feature switches: src/config/siteConfig.ts
- Navigation: src/config/navBarConfig.ts
- Avatar: src/assets/images/avatar.webp

The navigation keeps Home, Archive, My, About, Others, and GitHub. My contains Watch & Read, Diary, Albums, and My Devices. The Watch & Read page is for anime, manga, and light-novel services; Diary and Albums are reserved for personal memories and everyday life. The remaining template pages stay available through Others. The archive timeline will hold write-ups together with code, research papers, and study materials. The Links demo menu is removed because social links already live in the contact section. The sidebar keeps the profile, announcement, tags, table of contents, site statistics, calendar, categories, and local music player. The Live2D mascot remains enabled.

## Publish a post

Run `pnpm new-post -- my-first-writeup`, then edit the file under src/content/posts/. Keep unfinished posts marked `draft: true`. Published posts automatically appear on the homepage, archive timeline, search, and feeds. Related code, research papers, or slides can be stored under `public/resources/<post-slug>/` and linked from the Markdown post.

## Check and build

```sh
pnpm check
pnpm test
pnpm build
pnpm preview
```

## GitHub Pages

The deployment workflow builds pushes to master and writes the result to the pages branch. In repository Settings → Pages, select Deploy from a branch, then pages and / (root). Keep ENABLE_CONTENT_SYNC disabled to use this repository's local content.

For a private repository, GitHub Pages availability depends on the account plan. A pull request alone does not publish the site.

## Credits and licensing

Theme: [Mizuki](https://github.com/LyraVoid/Mizuki). See LICENSE, LICENSE.MIT, and THIRD_PARTY_NOTICES.md for the original licenses and asset notices.
