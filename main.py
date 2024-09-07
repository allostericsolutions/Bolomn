import streamlit as st
import itertools

# Implementación simplificada de la máquina Enigma
class Rotor:
    def __init__(self, wiring, notch):
        self.wiring = wiring
        self.notch = notch
        self.position = 0

    def set_position(self, position):
        self.position = position

    def forward(self, c):
        index = (ord(c) - ord('A') + self.position) % 26
        return self.wiring[index]

    def backward(self, c):
        index = (self.wiring.index(c) - self.position) % 26
        return chr(index + ord('A'))

class Reflector:
    def __init__(self, wiring):
        self.wiring = wiring

    def reflect(self, c):
        index = ord(c) - ord('A')
        return self.wiring[index]

class Plugboard:
    def __init__(self, connections):
        self.connections = connections

    def swap(self, c):
        return self.connections.get(c, c)

class EnigmaMachine:
    def __init__(self, rotors, reflector, plugboard):
        self.rotors = rotors
        self.reflector = reflector
        self.plugboard = plugboard

    def encrypt_decrypt(self, message):
        result = []
        for c in message:
            if c.isalpha():
                c = c.upper()
                c = self.plugboard.swap(c)
                for rotor in self.rotors:
                    c = rotor.forward(c)
                c = self.reflector.reflect(c)
                for rotor in reversed(self.rotors):
                    c = rotor.backward(c)
                c = self.plugboard.swap(c)
                result.append(c)
                self.advance_rotors()
            else:
                result.append(c)
        return ''.join(result)

    def advance_rotors(self):
        for i in range(len(self.rotors)):
            self.rotors[i].position = (self.rotors[i].position + 1) % 26
            if self.rotors[i].position != 0:
                break

# Función para descifrar con una configuración dada
def decrypt_with_positions(ciphertext, rotors, reflector, plugboard, positions):
    for i, rotor in enumerate(rotors):
        rotor.set_position(ord(positions[i]) - ord('A'))
    enigma = EnigmaMachine(rotors, reflector, plugboard)
    return enigma.encrypt_decrypt(ciphertext)

# Función para probar todas las configuraciones posibles
def brute_force_enigma(ciphertext, crib, rotors, reflector, plugboard):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    possible_rotor_positions = itertools.product(alphabet, repeat=3)
    for positions in possible_rotor_positions:
        decrypted_text = decrypt_with_positions(ciphertext, rotors, reflector, plugboard, positions)
        if crib in decrypted_text:
            return positions, decrypted_text
    return None, None

def main():
    st.title("Simulación de la Máquina Bombe")

    st.header("Entrada de Datos")
    ciphertext = st.text_input("Texto cifrado:")
    crib = st.text_input("Crib (texto conocido):")

    if st.button("Descifrar"):
        if ciphertext and crib:
            rotors = [
                Rotor("EKMFLGDQVZNTOWYHXUSPAIBRCJ", 16),
                Rotor("AJDKSIRUXBLHWTMCQGZNPYFVOE", 4),
                Rotor("BDFHJLCPRTXVZNYEIWGAKMUSQO", 21)
            ]
            reflector = Reflector("YRUHQSLDPXNGOKMIEBFZCWVJAT")
            plugboard = Plugboard({'A': 'B', 'B': 'A'})

            positions, decrypted_text = brute_force_enigma(ciphertext, crib, rotors, reflector, plugboard)
            if positions:
                st.write(f"Configuración encontrada: {positions}")
                st.write(f"Texto descifrado: {decrypted_text}")
            else:
                st.write("No se encontró una configuración correcta.")
        else:
            st.error("Por favor, ingrese el texto cifrado y el crib.")

if __name__ == "__main__":
    main()
