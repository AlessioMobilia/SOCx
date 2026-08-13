import { access, readFile } from "node:fs/promises"
import path from "node:path"

const targets = [
  {
    name: "Chrome",
    directory: "chrome-mv3-prod",
    manifestVersion: 3,
    panelKey: "side_panel",
    backgroundKey: "service_worker"
  },
  {
    name: "Edge",
    directory: "edge-mv3-prod",
    manifestVersion: 3,
    panelKey: "side_panel",
    backgroundKey: "service_worker"
  },
  {
    name: "Firefox",
    directory: "firefox-prod",
    manifestVersion: 2,
    panelKey: "sidebar_action",
    backgroundKey: "scripts"
  }
]

const failures = []

const assert = (condition, message) => {
  if (!condition) failures.push(message)
}

const assertFile = async (root, relativePath, context) => {
  try {
    await access(path.join(root, relativePath))
  } catch {
    failures.push(`${context}: missing referenced file ${relativePath}`)
  }
}

for (const target of targets) {
  const root = path.resolve("build", target.directory)
  const manifestPath = path.join(root, "manifest.json")
  let manifest

  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"))
  } catch (error) {
    failures.push(
      `${target.name}: cannot read ${manifestPath}: ${error.message}`
    )
    continue
  }

  assert(
    manifest.manifest_version === target.manifestVersion,
    `${target.name}: expected Manifest V${target.manifestVersion}`
  )
  assert(
    Boolean(manifest[target.panelKey]),
    `${target.name}: missing ${target.panelKey}`
  )
  assert(
    Boolean(manifest.background?.[target.backgroundKey]),
    `${target.name}: missing background.${target.backgroundKey}`
  )
  assert(
    !manifest.permissions?.includes("file:///*") ||
      target.manifestVersion === 2,
    `${target.name}: file:///* must be a host permission in Manifest V3`
  )

  if (target.name === "Firefox") {
    assert(
      manifest.browser_specific_settings?.gecko?.id ===
        "{017bef1c-5ecb-4a2e-a111-244174e2d9d8}",
      "Firefox: missing or unexpected AMO extension ID"
    )
  }

  const referencedFiles = [
    ...Object.values(manifest.icons ?? {}),
    manifest.action?.default_popup,
    manifest.browser_action?.default_popup,
    manifest.options_ui?.page,
    manifest.side_panel?.default_path,
    manifest.sidebar_action?.default_panel,
    manifest.background?.service_worker,
    ...(manifest.background?.scripts ?? []),
    ...(manifest.content_scripts ?? []).flatMap((entry) => [
      ...(entry.js ?? []),
      ...(entry.css ?? [])
    ])
  ].filter(Boolean)

  await Promise.all(
    referencedFiles.map((file) => assertFile(root, file, target.name))
  )
}

if (failures.length > 0) {
  console.error("Build validation failed:")
  failures.forEach((failure) => console.error(`- ${failure}`))
  process.exitCode = 1
} else {
  console.log("Chrome, Edge, and Firefox build manifests are valid.")
}
