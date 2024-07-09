import streamlit as st
import sqlite3
import hashlib
import random
import string
import logging
from datetime import datetime
from google.generativeai import configure, GenerativeModel
import time

# Configure the AI model
configure(api_key=st.secrets["api_key"])
model = GenerativeModel('gemini-pro')
st.set_page_config(page_title="PING", page_icon="⚡", layout="wide", initial_sidebar_state="expanded")
# Initialize database connection
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    is_admin INTEGER DEFAULT 0,
                    temporary_password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    message TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS temporary_passwords (
                    password TEXT PRIMARY KEY)''')
    conn.commit()
    return conn

# Add a new user to the database
def register_user(username, password):
    conn = init_db()
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

# Validate user login
def login_user(username, password):
    conn = init_db()
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, hashed_password))
    user = c.fetchone()

    # Check for temporary password if normal password fails
    if not user:
        c.execute("SELECT * FROM users WHERE username = ? AND temporary_password = ?", (username, password))
        user = c.fetchone()

        if user:
            # Prevent misuse by verifying the user previously had the password reset
            c.execute("SELECT temporary_password FROM users WHERE username = ?", (username,))
            stored_temp_password = c.fetchone()
            if stored_temp_password[0] != password:
                user = None

    conn.close()
    return user

# Check if user is an admin
def is_admin(username):
    conn = init_db()
    c = conn.cursor()
    c.execute("SELECT is_admin FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user[0] == 1 if user else False

# Add a message to the database
def add_message(username, message):
    conn = init_db()
    c = conn.cursor()
    c.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
    conn.commit()
    conn.close()

# Retrieve messages from the database
def get_messages():
    conn = init_db()
    c = conn.cursor()
    c.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC")
    messages = c.fetchall()
    conn.close()
    return messages

# Generate a temporary password
def get_temp_password():
    conn = init_db()
    c = conn.cursor()
    c.execute("SELECT password FROM temporary_passwords LIMIT 1")
    temp_password = c.fetchone()
    if temp_password:
        c.execute("DELETE FROM temporary_passwords WHERE password = ?", (temp_password[0],))
        conn.commit()
    conn.close()
    return temp_password[0] if temp_password else None

# Assign a temporary password to a user
def assign_temp_password(username, temp_password):
    conn = init_db()
    c = conn.cursor()
    c.execute("UPDATE users SET temporary_password = ? WHERE username = ?", (temp_password, username))
    conn.commit()
    conn.close()

# Streamlit UI Components

def login_form():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.username = username
            st.session_state.logged_in = True
            st.session_state.is_admin = is_admin(username)
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")


# Configure logging
logging.basicConfig(level=logging.INFO)

def admin_login_form():
    st.subheader("Admin Login")
    username = st.text_input("Admin Username")
    password = st.text_input("Admin Password", type="password")
    if st.button("Login"):
        admin_username = st.secrets["admin_username"]
        admin_password = st.secrets["admin_password"]
        logging.info(f"Attempting admin login with username: {username}")
        if username == admin_username and password == admin_password:
            st.session_state.username = username
            st.session_state.logged_in = True
            st.session_state.is_admin = True
            logging.info(f"Admin login successful for username: {username}")
            st.experimental_rerun()
        else:
            logging.warning(f"Admin login failed for username: {username}")
            st.error("Invalid admin username or password")

# Register form
def register_form():
    st.subheader("Register")
    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    password_confirm = st.text_input("Confirm Password", type="password")
    if st.button("Register"):
        if password == password_confirm:
            try:
                register_user(username, password)
                st.success("User registered successfully")
            except sqlite3.IntegrityError:
                st.error("Username already exists")
        else:
            st.error("Passwords do not match")

# Forgot password form
def forgot_password_form():
    st.subheader("Forgot Password")
    username = st.text_input("Username")
    if st.button("Submit"):
        temp_password = get_temp_password()
        if temp_password:
            assign_temp_password(username, temp_password)
            st.info(f"Your temporary password is: {temp_password}. Please use this to log in.")
        else:
            st.error("No temporary passwords available. Please contact support.")

# Delete Account form
def delete_account_form():
    st.subheader("Delete Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Delete Account"):
        user = login_user(username, password)
        if user:
            conn = init_db()
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()
            st.success("Account deleted successfully")
        else:
            st.error("Invalid username or password")

# Admin interface
def admin_interface():
    st.image("ping.png", use_column_width=True)
    st.title(f"Welcome, {st.session_state['username']}!")
    action = st.selectbox("Admin Actions",
                          ["View Users", "Delete User", "Modify User", "Add Temporary Passwords", "View Messages",
                           "Delete Message", "Delete All Messages"])

    if st.button("Logout"):
        for key in st.session_state.keys():
            del st.session_state[key]
        st.experimental_rerun()

    if action == "View Users":
        conn = init_db()
        c = conn.cursor()
        c.execute("SELECT username, is_admin FROM users")
        users = c.fetchall()
        conn.close()
        st.write(users)

    elif action == "Delete User":
        user_to_delete = st.text_input("Enter username to delete")
        if st.button("Delete User"):
            conn = init_db()
            c = conn.cursor()
            c.execute("DELETE FROM users WHERE username = ?", (user_to_delete,))
            conn.commit()
            conn.close()
            st.success("User deleted successfully.")

    elif action == "Modify User":
        user_to_modify = st.text_input("Enter username to modify")
        new_password = st.text_input("Enter new password", type="password")
        if st.button("Modify User"):
            conn = init_db()
            c = conn.cursor()
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, user_to_modify))
            conn.commit()
            conn.close()
            st.success("User modified successfully.")

    elif action == "Add Temporary Passwords":
        num_passwords = st.number_input("Number of temporary passwords to add", min_value=1, step=1)
        if st.button("Add Passwords"):
            conn = init_db()
            c = conn.cursor()
            for _ in range(num_passwords):
                temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
                c.execute("INSERT INTO temporary_passwords (password) VALUES (?)", (temp_password,))
            conn.commit()
            conn.close()
            st.success(f"Added {num_passwords} temporary passwords.")

    elif action == "View Messages":
        messages = get_messages()
        st.write(messages)

    elif action == "Delete Message":
        message_id = st.number_input("Enter message ID to delete", min_value=1, step=1)
        if st.button("Delete Message"):
            conn = init_db()
            c = conn.cursor()
            c.execute("DELETE FROM messages WHERE id = ?", (message_id,))
            conn.commit()
            conn.close()
            st.success("Message deleted successfully.")
    elif action == "Delete All Messages":
        if st.button("Confirm Delete All Messages"):
            conn = init_db()
            c = conn.cursor()
            c.execute("DELETE FROM messages")
            conn.commit()
            conn.close()
            st.success("All messages deleted successfully.")

# Chat interface with AI integration
def chat_interface():
    st.subheader(f"Welcome, {st.session_state.username}!")

    if st.button("Logout"):
        for key in st.session_state.keys():
            del st.session_state[key]
        st.experimental_rerun()

    message = st.text_input("Type your message", key="unique_message_input")

    if st.button("Send"):
        if message:
            add_message(st.session_state.username, message)

            # Check for @autobot and get AI response
            if "@autobot" in message:
                with st.spinner("Generating response..."):
                    try:
                        question = message.replace("@autobot", "").strip()
                        response = model.generate_content(question)
                        if response.text:
                            ai_response = f"{st.session_state['username']} pinged Autobot about {question}, " \
                                          f"Here is the response: {response.text}"
                            add_message("AutoBot", ai_response)
                        else:
                            st.error("No valid response received from the AI model.")
                    except Exception as e:
                        st.error(f"An error occurred: {e}")

            # Refresh the page to clear the input field
            st.experimental_rerun()
        else:
            st.error("Please enter a message.")

    # Message display container with auto-refresh
    messages = get_messages()
    st.markdown(
        """
        <style>
        body {
            background-color: #121212;
            color: #E0E0E0;
        }
        .message-container {
            max-width: 700px;
            margin: 0 auto;
            padding: 20px;
            background-color: #1E1E1E;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .message {
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            background-color: #2A2A2A;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .message-header {
            font-weight: bold;
            margin-bottom: 5px;
            color: #BB86FC;
        }
        .message-timestamp {
            font-size: 0.8em;
            color: #BB86FC;
        }
        </style>
        <div class="message-container"><big><b>Messages</b></big></div>
        """,
        unsafe_allow_html=True
    )

    message_ids = [msg[0] for msg in messages]

    for msg in messages:
        st.markdown(
            f"""
            <div class="message">
                <div class="message-header">{msg[1]}</div>
                <div>{msg[2]}</div>
                <div class="message-timestamp">{msg[3]}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # Refresh messages every 3 seconds
    st.button("Refresh", on_click=st.experimental_rerun)
    time.sleep(2)
    st.experimental_rerun()

# Main application logic
def main():
    st.title("PING ⚡")
    if 'username' not in st.session_state:
        st.session_state['username'] = ""
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
    if 'is_admin' not in st.session_state:
        st.session_state['is_admin'] = False

    if st.session_state.logged_in:
        if st.session_state.is_admin:
            admin_interface()
        else:
            chat_interface()
    else:
        st.sidebar.image("ping.png", use_column_width=True)
        option = st.sidebar.selectbox("Select an option", ["Login", "Register", "Forgot Password", "Delete Account", "Admin Login"])
        if option == "Login":
            login_form()
        elif option == "Register":
            register_form()
        elif option == "Forgot Password":
            forgot_password_form()
        elif option == "Delete Account":
            delete_account_form()
        elif option == "Admin Login":
            admin_login_form()

if __name__ == "__main__":
    main()
