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

function toggleDarkMode() {
  var element = document.getElementById("parent");
  element.classList.toggle("dark");
}