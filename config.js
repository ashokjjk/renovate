module.exports = {
  platform: "bitbucket",
  username: `${process.env.BITBUCKET_USERNAME}`,
  password: `${process.env.BITBUCKET_APP_PASSWORD}`,
  baseDir: `${process.env.BITBUCKET_CLONE_DIR}/renovate`,
  autodiscover: false,
  baseBranches: ["main"],

  repositories: [
    "ifs-pd/nexus-platform-core",
  ],

  // Recreate declined PR
  recreateWhen: "always",

  // PR configuration
  prTitle: "chore(deps): update {{depName}} from {{currentVersion}} to {{newVersion}}",
  prBodyColumns: [
    "Package",
    "Update",
    "Change",
    "Digest",
    "ChartName",
    "CurrentVersion",
    "NewVersion",

  ],
  prBodyDefinitions: {
    Package: "{{depName}}",
    Update: "{{#if currentVersion}}{{currentVersion}}{{#if digest}}{{digest}}{{/if}}{{/if}} → {{#if newVersion}}{{newVersion}}{{#if newDigest}}{{newDigest}}{{/if}}{{/if}}",
    Change: "{{#if isMajor}}major{{else if isMinor}}minor{{else}}patch{{/if}}",
    Digest: "{{#if newDigest}}{{newDigest}}{{else}}N/A{{/if}}",
    ChartName: "{{depName}}",
    CurrentVersion: "{{currentVersion}}",
    NewVersion: "{{newVersion}}",
    NewDigest: "{{#if newDigest}}{{newDigest}}{{else}}N/A{{/if}}",
    UpdateType: "{{#if isMajor}}major{{else if isMinor}}minor{{else}}patch{{/if}}"
  },
  prBody: "This PR updates the Helm chart {{depName}} from version {{currentVersion}} to {{newVersion}}.\n\n{{#if newDigest}}New digest: {{newDigest}}{{/if}}\n\nChanges will be tested with Chainsaw before merging.",
  labels: ["dependencies", "chainsaw-test"],
  commitMessage: "chore(deps): update {{depName}} to {{newVersion}}"
};
