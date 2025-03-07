import streamlit as st
import random
import string

st.set_page_config(page_title="Password_Strength_Meter", page_icon="🔐", layout="wide")

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: whitesmoke;
    }}

    .stSlider > div > div > div > div > div {{
        color: rgb(39, 38, 37);
    }}

    .stSlider > div > div > div > div {{
        background-color: gray;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

st.title("Password_Strength_Meter")

length = st.slider(label="Length", min_value=8, max_value=25)
uppercase = st.checkbox(label="Uppercase")
lowercase = st.checkbox(label="Lowercase")
digits = st.checkbox(label="Digits")
special_characters = st.checkbox(label="Special haracters (!@#$%^&*_)")

def generate_password(length, uppercase, lowercase, digits, special_characters):
    score = 0
    characters = string.whitespace
    color = ""

    if uppercase:
        characters += string.ascii_uppercase
        score += 1
   
    if lowercase:
        characters += string.ascii_lowercase
        score += 1

    if digits:
        characters += string.digits
        score += 1

    if special_characters:
        characters += string.punctuation
        score += 1

    if uppercase and lowercase and digits and special_characters:
        st.success("Strong password")
    elif uppercase and lowercase and digits:
        st.warning("Moderate password.. add special characters")
    elif uppercase and lowercase and special_characters:
        st.warning("Common password.. add digits")
    elif not uppercase and not lowercase and not digits and not special_characters:
        st.warning("Please select above features.")
    else:
        st.warning("Weak password.. use above features.")

    total = (score / 4) * 100

    if total == 100:
        color = "green"
    elif total == 75:
        color = "yellow"
    elif total == 50:
        color = "orange"
    elif total == 25:
        color = "red"

    st.markdown(
        f"""
            <style>
            .stProgress > div > div > div > div {{
                background-color: {color};              
            }}
            </style>
        """,
        unsafe_allow_html=True
    )

    st.progress(int(total))
    st.write(f"Password Strength: {int(total)}%")

    return "".join(random.choice(characters) for _ in range(length))

if st.button(label="Generate Password"):
    password = generate_password(length, uppercase, lowercase, digits, special_characters)
    st.write(f"Your generated password is: {password}")

    st.code(password, language="")

    st.markdown(
    f"""
    <style>
    .copy {{
        border: none;
    }}
    </style>
    <button class="copy" onclick="navigator.clipboard.writeText('{password}').then(() => alert('Copied!'))">
    </button>
    """,
    unsafe_allow_html=True
    )
