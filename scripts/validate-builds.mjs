import { access, readdir, readFile } from "node:fs/promises"
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

const runtimeModuleSpecifiers = [
  "@heroicons/react",
  "@plasmohq/messaging",
  "@plasmohq/storage",
  "react",
  "react/jsx-runtime",
  "react-dom/client",
  "react-icons",
  "tippy.js",
  "xlsx-js-style"
]

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

const findFiles = async (root, extension) => {
  const entries = await readdir(root, { withFileTypes: true })
  const nestedFiles = await Promise.all(
    entries.map((entry) => {
      const entryPath = path.join(root, entry.name)
      return entry.isDirectory()
        ? findFiles(entryPath, extension)
        : entry.name.endsWith(extension)
          ? [entryPath]
          : []
    })
  )

  return nestedFiles.flat()
}

const assertRuntimeModulesAreBundled = async (root, context) => {
  const javascriptFiles = await findFiles(root, ".js")

  for (const file of javascriptFiles) {
    const contents = await readFile(file, "utf8")
    const unresolvedModules = runtimeModuleSpecifiers.filter((specifier) =>
      contents.includes(`"${specifier}":"${specifier}"`)
    )

    assert(
      unresolvedModules.length === 0,
      `${context}: ${path.relative(root, file)} leaves runtime modules external: ${unresolvedModules.join(", ")}`
    )
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
    const requiredData =
      manifest.browser_specific_settings?.gecko?.data_collection_permissions
        ?.required ?? []
    assert(
      requiredData.includes("authenticationInfo") &&
        requiredData.includes("websiteContent"),
      "Firefox: missing required data-collection declarations"
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
  await assertRuntimeModulesAreBundled(root, target.name)
}

if (failures.length > 0) {
  console.error("Build validation failed:")
  failures.forEach((failure) => console.error(`- ${failure}`))
  process.exitCode = 1
} else {
  console.log(
    "Chrome, Edge, and Firefox manifests, files, and runtime bundles are valid."
  )
}
