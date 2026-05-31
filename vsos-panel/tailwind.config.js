/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0F0F1A',
        surface: '#1B1B2E',
        elevated: '#232336',
        hover: '#2A2A42',
        border: '#2E2E4A',
        'border-subtle': '#24243A',
        accent: '#5E6AD2',
        'accent-hover': '#6E7AE2',
        primary: '#F1F1F4',
        secondary: '#9B9BAD',
        muted: '#6B6B80',
      },
    },
  },
  plugins: [],
}
