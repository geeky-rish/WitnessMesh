/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sidebar: '#19496B',
        'sidebar-text': '#E8EDF1',
        'main-bg': '#F2F3F4',
        'card-bg': '#FFFFFF',
        primary: '#328C89',
        'primary-hover': '#2A7A77',
        'text-primary': '#233746',
        'text-secondary': '#75818A',
        success: '#27865B',
        warning: '#D69A32',
        danger: '#C74747',
        border: '#DCE1E5',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}