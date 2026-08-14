import { spawn } from "node:child_process"
import { pathToFileURL } from "node:url"

export const buildFirefoxPublishArguments = ({
  sourceDirectory,
  sourceArchive,
  artifactsDirectory = "build/firefox-signed"
}) => [
  "dlx",
  "web-ext@10.6.0",
  "sign",
  "--channel=listed",
  `--source-dir=${sourceDirectory}`,
  `--artifacts-dir=${artifactsDirectory}`,
  `--upload-source-code=${sourceArchive}`,
  "--approval-timeout=900000",
  "--timeout=900000",
  "--no-input",
  "--verbose"
]

export const publishFirefoxExtension = async ({
  credentials,
  sourceDirectory,
  sourceArchive,
  spawnImpl = spawn
}) => {
  const { apiKey, apiSecret } = credentials ?? {}
  if (!apiKey || !apiSecret) {
    throw new Error("SUBMIT_KEYS.firefox must contain apiKey and apiSecret")
  }

  const childEnvironment = { ...process.env }
  delete childEnvironment.SUBMIT_KEYS
  childEnvironment.WEB_EXT_API_KEY = apiKey
  childEnvironment.WEB_EXT_API_SECRET = apiSecret

  const command = process.platform === "win32" ? "pnpm.cmd" : "pnpm"
  const args = buildFirefoxPublishArguments({
    sourceDirectory,
    sourceArchive
  })

  await new Promise((resolve, reject) => {
    const child = spawnImpl(command, args, {
      env: childEnvironment,
      stdio: "inherit"
    })
    child.once("error", reject)
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolve()
        return
      }
      reject(
        new Error(
          `Firefox publication failed${signal ? ` with signal ${signal}` : ` with exit code ${code}`}`
        )
      )
    })
  })
}

const isCli =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href

if (isCli) {
  const submitKeys = JSON.parse(process.env.SUBMIT_KEYS || "{}")
  await publishFirefoxExtension({
    credentials: submitKeys.firefox,
    sourceDirectory: process.env.FIREFOX_SOURCE_DIR || "build/firefox-prod",
    sourceArchive:
      process.env.FIREFOX_SOURCE_ZIP || "dist/source_for_review.zip"
  })
}
