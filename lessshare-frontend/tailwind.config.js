/** @type {import('tailwindcss').Config} */
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{vue,js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'blade-cyan': '#0ff',
        'blade-purple': '#8a2be2',
      },
      fontFamily: {
        'tech': ['"Share Tech Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}