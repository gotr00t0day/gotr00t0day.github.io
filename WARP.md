# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This repository contains a cybersecurity researcher's personal portfolio website hosted on GitHub Pages. The site showcases security research, vulnerability discoveries (CVEs), penetration testing guides, and security tools developed by gotr00t0day.

## Site Architecture

### Core Structure
- **Static HTML Website**: Single-page application architecture with multiple HTML files
- **Self-contained Design**: All CSS and JavaScript are embedded within HTML files (no external dependencies except CDN resources)
- **Responsive Layout**: Mobile-first design with CSS Grid and Flexbox
- **Consistent Theming**: Dark cybersecurity aesthetic with glowing white accents

### Main Pages
- `index.html`: Homepage with personal introduction and skill showcase
- `poc.html`: CVE Arsenal showcasing 16 discovered vulnerabilities with CVSS scores
- `projects.html`: Underground Arsenal featuring 8 security tools and frameworks
- `guides.html`: Comprehensive security guides organized by category (13 total guides)
- `contact.html`: Professional contact information and social media links

### Content Organization
- `Guides/`: Markdown files containing detailed security guides
  - Active Directory pentesting
  - Windows/Linux security hardening  
  - EDR/AV bypass techniques
  - PowerShell and Python security guides
  - Red team operations and exploitation techniques

## Development Commands

### Local Development
```bash
# Serve the website locally using Python
python3 -m http.server 8000
# Access at http://localhost:8000

# Alternative using Node.js
npx http-server .
```

### GitHub Pages Deployment
```bash
# Automatic deployment on push to main branch
git add .
git commit -m "Update website content"
git push origin main

# Check deployment status
# Visit: https://github.com/gotr00t0day/gotr00t0day.github.io/deployments
```

### Content Validation
```bash
# Validate HTML structure
npx html-validate *.html

# Check for broken links
npx broken-link-checker http://localhost:8000

# Optimize images (if adding new images)
npx imagemin gotr00t_wallpaper.png --out-dir=optimized
```

## Code Architecture

### Styling System
- **Consistent Color Palette**: Black gradients (#000000, #0a0a0a, #111111) with white (#ffffff) accents
- **Typography**: 'Share Tech Mono' for body text, 'Orbitron' for headers
- **Animation Framework**: CSS keyframe animations for glowing effects, binary backgrounds, and hover states
- **Component-Based CSS**: Each page reuses similar card components with consistent styling patterns

### Navigation System
- **Static Navigation**: Inline navigation links on each page (no JavaScript routing)
- **Active State Management**: CSS-based active states for current page indication
- **Mobile Responsive**: Collapsible navigation for mobile devices

### Data Management
- **Hardcoded Content**: All CVE data, projects, and statistics are hardcoded in HTML
- **External Links**: Heavy use of GitHub repository links and external CVE databases
- **No Backend**: Purely static site with no server-side functionality

### Interactive Features
- **JavaScript Enhancements**: Terminal-style loading prompts, hover effects, dropdown toggles
- **Animation System**: Coordinated CSS animations for professional cybersecurity aesthetic
- **Card Interactions**: Hover states with glow effects and elevation changes

## Key Components

### CVE Showcase System
- **Vulnerability Cards**: Standardized layout for displaying CVE information
- **Severity Badges**: Color-coded CVSS score indicators
- **GitHub Integration**: Direct links to proof-of-concept repositories
- **Statistics Dashboard**: Automated counters for research metrics

### Project Portfolio System
- **Tool Categories**: Organized by function (Reconnaissance, Exploitation, Bypass, etc.)
- **GitHub Stars Integration**: Manual tracking of repository popularity
- **Language Tags**: Technology stack indicators for each project

### Guide Management System
- **Categorical Organization**: Dropdown-based guide organization
- **Markdown Integration**: External markdown files referenced from HTML
- **Progressive Disclosure**: Collapsible categories for better UX

## Content Management

### Adding New CVEs
1. Update `poc.html` with new CVE card following existing structure
2. Include CVSS score, vulnerability type, and GitHub repository link
3. Update statistics counters in the stats-section div
4. Maintain consistent severity badge styling

### Adding New Projects
1. Update `projects.html` with new project card
2. Include project description, language tags, and GitHub stars
3. Ensure proper exploit-badge categorization
4. Add repository links following existing pattern

### Adding New Guides
1. Create markdown file in `Guides/` directory
2. Update `guides.html` with new guide entry in appropriate category
3. Update guide counts in category headers
4. Ensure proper GitHub repository linking

## GitHub Pages Configuration

### Repository Settings
- **Branch**: Deploys from main branch
- **Custom Domain**: None (uses gotr00t0day.github.io)
- **HTTPS**: Enforced through GitHub Pages settings
- **Build Process**: Static file serving (no Jekyll processing)

### Performance Considerations
- **CDN Resources**: Font Awesome and Google Fonts loaded from CDN
- **Image Optimization**: Single logo image (gotr00t_wallpaper.png) used across site
- **CSS/JS Inlining**: All styles and scripts embedded to reduce HTTP requests

## Security Considerations

### Content Security
- **External Links**: All external links open in new tabs with security considerations
- **No User Input**: No forms or user-generated content to secure
- **Static Content**: No server-side processing reduces attack surface

### Privacy Features
- **No Analytics**: No tracking scripts or analytics platforms integrated
- **Minimal Data Collection**: Only external CDN resources loaded
- **Contact Information**: Public social media links only, no private contact details

## Browser Compatibility

### Supported Features
- **CSS Grid**: Used extensively for layout (IE11+ support needed)
- **CSS Animations**: Keyframe animations for visual effects
- **ES6 JavaScript**: Modern JavaScript features used minimally
- **Font Loading**: Google Fonts with fallbacks to system fonts

### Testing Checklist
- Verify animations work smoothly across browsers
- Test responsive breakpoints on various screen sizes
- Ensure all GitHub links are functional and current
- Validate CDN resource loading
- Check mobile navigation functionality

## Maintenance Notes

### Regular Updates Required
- **CVE Statistics**: Update discovery counts and GitHub stars manually
- **Project Status**: Maintain current repository information and star counts
- **Guide Content**: Keep security guides current with latest techniques
- **Link Validation**: Periodically check all external GitHub repository links

### Performance Monitoring
- **Page Load Speed**: Monitor loading times, especially with animations
- **GitHub Pages Status**: Check deployment status for any failures
- **CDN Availability**: Monitor external font and icon loading

This website serves as both a professional portfolio and educational resource for the cybersecurity community, showcasing practical security research and tool development expertise.
