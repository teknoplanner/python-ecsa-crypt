module.exports = {
  mode: 'jit',
  purge: ['./templates/*.html'],
  darkMode: 'class', // or 'media' or 'class'
  theme: {
    backgroundImage: {
      'image1': "url('./static/images/macbook.svg')",
    },
    extend: {},
  },
  variants: {
    extend: {},
  },
  plugins: [require("daisyui")],
}

