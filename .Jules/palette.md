## 2024-07-16 - Add ARIA Labels to Topology Panel Icons
**Learning:** Found that custom icon-only buttons in the topology faceplate panel (using monospace '⤢' and '✕') lacked both accessible names and standard tooltip text. This is a common pattern in complex data visualization UI.
**Action:** Always add 'aria-label' and 'title' attributes to buttons where text content is purely symbolic or iconic.
