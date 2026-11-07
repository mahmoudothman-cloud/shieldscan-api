import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "coverage"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.strict],
    files: ["**/*.{ts,tsx}"],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { "react-hooks": reactHooks, "react-refresh": reactRefresh },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // CONSTITUTION §13.4: no `any`.
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    // Tests index into recorded mock calls; a non-null assertion there is
    // the honest spelling (a missing call fails the test either way).
    files: ["**/*.test.{ts,tsx}", "src/test/**"],
    rules: { "@typescript-eslint/no-non-null-assertion": "off" },
  },
);
