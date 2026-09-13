# Sentinal visual direction

The console uses the owner's supplied palette: sage #84918F, warm ivory #E9E3E0,
and taupe #BDAB9C. Dark green neutrals provide readable foregrounds; these decorative
palette colors are not used as low-contrast small text.

The requested reference is https://www.micro1.ai/. Its public page text was accessible,
but browser policy verification prevented visual inspection. This implementation is an
original interpretation, not a pixel match or a claim to use micro1's exact typeface.
Typography uses Helvetica Neue, Helvetica and Arial with a generic sans-serif fallback;
no external font requests or licensed font files are added.

The original foundation.svg illustrates nested architectural arches in the supplied
palette. It is served locally, contains no scripts or external resources, and has an
accessible description. The composition combines a large headline, editorial spacing,
a quiet image panel and an explicitly separated working environment.

Existing control identifiers, scripts, permissions and server behavior are preserved.
The two governance switches remain independently controlled. Disconnected controls
continue to display Unknown. Navigation uses in-page anchors; a skip link leads to the
workspace. Small-screen rules stack panels and forms, and the audit table can scroll
inside its own region. Smooth scrolling respects reduced-motion preferences.

Verification: control interaction tests and Python tests, static anchor/ID/SVG checks
and calculations for core foreground/background contrast. Desktop/mobile screenshots,
keyboard flow and rendered layout remain unverified because browser policy checks were
unavailable. This is a draft design, not a deployment or an accessibility certification.
