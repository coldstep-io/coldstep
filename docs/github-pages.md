# ColdStep.io — GitHub Pages checklist

Use this checklist after the static site and workflow are on the default branch you deploy from (typically **`main`**).

## What is in the repository

| Path | Purpose |
| :--- | :------ |
| `website/` | Static site: `index.html`, `styles.css`, `favicon.svg` |
| `.github/workflows/coldstep-pages.yml` | Builds and deploys **`website/`** to GitHub Pages |

The workflow runs on:

- Push to **`main`** when **`website/**`** or **`coldstep-pages.yml`** changes
- **`workflow_dispatch`** (manual run)

## One-time: enable Pages in GitHub

1. Open the repo on GitHub: **https://github.com/coldstep-io/coldstep**
2. Go to **Settings → Pages**
3. Under **Build and deployment**, set **Source** to **GitHub Actions**  
   (Do not use “Deploy from a branch” unless you intentionally switch away from the Actions workflow.)
4. Save if prompted

## First deploy

1. Merge (or push) the branch that contains `website/` and `.github/workflows/coldstep-pages.yml` to **`main`**, **or**
2. Open **Actions**, select **coldstep-pages**, run **Run workflow** (**workflow_dispatch**)

After a successful run, open the **coldstep-pages** workflow run: the **github-pages** environment (or the job summary) should show the public URL. For an `org.github.io` style project site, it is often:

**`https://coldstep-io.github.io/coldstep/`**

(Exact URL depends on repo name and whether this is a user/org site vs project site.)

## Optional: custom domain (e.g. coldstep.io)

1. **Settings → Pages → Custom domain** — enter **`coldstep.io`** (or **`www.coldstep.io`**)
2. Complete GitHub’s **DNS** checks at your DNS host:
   - For **`www`**, a **CNAME** to **`coldstep-io.github.io`** is typical
   - For an **apex** (`coldstep.io` without `www`), follow GitHub’s docs for **ALIAS / ANAME** (provider-dependent)
3. Wait for DNS to propagate; keep **Enforce HTTPS** enabled once available
4. Optional: add a committed **`website/CNAME`** file whose only line is the hostname (e.g. `coldstep.io`) if you want the domain recorded in git — only do this when DNS is correct

## Verify locally (optional)

Open `website/index.html` in a browser from disk, or serve the folder with any static server, to review copy and layout before pushing.

## Note on `docs/`

The repository **`.gitignore`** ignores **`/docs/`**, so files under **`docs/`** are for local or out-of-band use unless you change ignore rules or copy this checklist elsewhere (for example into **`README.md`** or **`website/`**).
