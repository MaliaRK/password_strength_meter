import streamlit as st
import random
import string
import re
import bcrypt

st.set_page_config(page_title="Password_Strength_Meter", page_icon="🔐", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background-color: #b4b4b4;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("Make Your own password...!")
password_list = []

def password_generator(password):
    score = 0
    st.session_state.length = len(password)
    blacklist = ['password123', 'abc123', '123456789']

    if password.lower() in blacklist:
        st.error('This is a common password. Please choose another one.')
        return

    if st.session_state.length >= 8:
        score += 1
    else:
        st.warning("password should be at least 8 characters long.")

    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    else:
        st.warning("password should contain capital and small letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        st.warning("password should include atleast one digit (0-9).")

    if re.search(r"[!@#$%^&*_]", password):
        score += 1
    else:
        st.warning("password should have one special character (!@#$%^&*_).")
         
        if score > 0 and score <= 2:
            st.error("weak password! Make a strong password using above suggesstion.")
        elif score == 3:
            st.error("Good but add some security features.")
        
    if score == 4:
        st.success("strong password.")


password = st.text_input(label="Enter  Password: ", value="", key="password", on_change= None)
password_generator(password)

# password encryption
password_bytes = password.encode('utf-8')
salt = bcrypt.gensalt()
hashed_password = bcrypt.hashpw(password_bytes, salt)


re_enter_password = st.text_input(label="Re-Enter Password: ", key='re_enter')

re_enter_bytes = re_enter_password.encode('utf-8')

match = bcrypt.checkpw(re_enter_bytes, hashed_password)

if re_enter_password != "":
    if match:
        st.success('password matched!')
    else:
        st.error('password do not match')

if st.button(label='Generate password'):
    st.subheader(f"Password Generated! `{password}`")

st.write('-------------------------------------------------------')


st.title("Password Generator...!")

def generate_password(length, use_digits, use_special):
    characters = string.ascii_letters

    if use_digits:
        characters += string.digits

    if use_special:
        characters += string.punctuation

    return "".join(random.choice(characters) for _ in range(length))

length = st.slider(label='Select password length:', min_value=6, max_value=25, value=8)

use_digits =  st.checkbox(label='Include numbers')

use_special = st.checkbox(label='Include special characters')

if st.button(label='Generate Password'):
    password = generate_password(length, use_digits, use_special)
    st.write(f"Generated Password: `{password}`")
