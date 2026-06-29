export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'dark': {
          'bg': '#0a0a0e',
          'sidebar': '#0f1419',
          'card': '#151b28',
          'border': '#1f2937',
          'hover': '#1a2332',
          'text-secondary': '#aaaaaa',
        },
        'accent': {
          'cyan': '#00d4ff',
          'red': '#ff0055',
          'green': '#00ff88',
          'orange': '#ffaa00',
          'purple': '#b066ff',
        },
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
