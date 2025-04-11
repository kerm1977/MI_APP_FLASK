function limpiarNumero(input) {
  // Elimina cualquier carácter que no sea un número
  input.value = input.value.replace(/[^0-9]/g, '');
}