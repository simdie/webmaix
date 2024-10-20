/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html', // Adjust this path according to your project structure
    './static/js/**/*.js',   // Include paths to any JavaScript files that use Tailwind classes
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}
