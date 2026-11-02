import json
import time
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.scrollview import ScrollView
from kivy.clock import Clock
from kivy.network.urlrequest import UrlRequest
from cryptography.fernet import Fernet

STATIC_KEY = b'6c-NfG71TzE5x4_VwK7u_PZ7N5D1q-99V3eX9_b5H40='
cipher_suite = Fernet(STATIC_KEY)

# Change this to your public server IP address when deploying over cellular data
SERVER_URL = "http://127.0.0.1:5000"

# Section 3: local retention policy (seconds)
RETENTION_SECONDS = 1800


class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=30, spacing=15)
        layout.add_widget(Label(text="P/M - Private Messenger", font_size=24, size_hint_y=None, height=50))

        # Section 2: static credential gate
        self.username_input = TextInput(hint_text="Username", text="OT76", multiline=False, write_tab=False, size_hint_y=None, height=50)
        self.password_input = TextInput(hint_text="Password", text="love you", password=True, multiline=False, write_tab=False, size_hint_y=None, height=50)

        layout.add_widget(self.username_input)
        layout.add_widget(self.password_input)

        login_btn = Button(text="Login", size_hint_y=None, height=50, background_color=(0, 0.5, 1, 1))
        login_btn.bind(on_press=self.validate_credentials)
        layout.add_widget(login_btn)

        self.error_label = Label(text="", color=(1, 0, 0, 1), size_hint_y=None, height=30)
        layout.add_widget(self.error_label)
        self.add_widget(layout)

    def validate_credentials(self, instance):
        if self.username_input.text == "OT76" and self.password_input.text == "love you":
            self.manager.current = 'chat'
        else:
            self.error_label.text = "Invalid credentials. Access Denied."


class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super(ChatScreen, self).__init__(**kwargs)
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)

        self.local_vault = []
        self.last_index = 0  # server cursor, prevents duplicate re-decryption on poll

        self.scroll = ScrollView(size_hint=(1, 0.85))
        self.chat_history = BoxLayout(orientation='vertical', spacing=5, size_hint_y=None)
        self.chat_history.bind(minimum_height=self.chat_history.setter('height'))
        self.scroll.add_widget(self.chat_history)
        layout.add_widget(self.scroll)

        input_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.15), spacing=5)
        self.msg_input = TextInput(hint_text="Type encrypted message...", multiline=False, write_tab=False)
        send_btn = Button(text="Send", size_hint_x=0.25, background_color=(0, 0.6, 0.3, 1))
        send_btn.bind(on_press=self.send_message)

        input_layout.add_widget(self.msg_input)
        input_layout.add_widget(send_btn)
        layout.add_widget(input_layout)
        self.add_widget(layout)

        Clock.schedule_interval(self.poll_network, 2.0)
        Clock.schedule_interval(self.enforce_retention_policy, 5.0)

    def send_message(self, instance):
        text = self.msg_input.text.strip()
        if not text:
            return

        # Section 4: encrypt payload on-device before transport
        encrypted_text = cipher_suite.encrypt(text.encode()).decode()
        self.append_to_history(f"Me: {text}")
        self.msg_input.text = ""

        payload = json.dumps({"sender": "OT76", "payload": encrypted_text})
        headers = {'Content-type': 'application/json'}
        UrlRequest(f"{SERVER_URL}/send", req_body=payload, req_headers=headers)

    def poll_network(self, dt):
        UrlRequest(f"{SERVER_URL}/get?after={self.last_index}", on_success=self.on_poll_success)

    def on_poll_success(self, request, result):
        try:
            self.last_index = max(self.last_index, int(result.get("last_index", 0)))
            for msg in result.get("messages", []):
                if msg.get("sender") != "OT76":
                    decrypted = cipher_suite.decrypt(msg["payload"].encode()).decode()
                    self.append_to_history(f"Peer: {decrypted}")
        except Exception:
            pass

    def append_to_history(self, text):
        lbl = Label(text=text, size_hint_y=None, height=30, halign='left', valign='middle')
        lbl.bind(size=lbl.setter('text_size'))
        self.chat_history.add_widget(lbl)

        self.local_vault.append({
            "timestamp": time.time(),
            "text": text,
            "widget": lbl
        })

    # Section 3: purge expired message records + their layout nodes
    def enforce_retention_policy(self, dt):
        now = time.time()
        expired_records = [msg for msg in self.local_vault if (now - msg["timestamp"]) > RETENTION_SECONDS]

        for record in expired_records:
            if record["widget"] in self.chat_history.children:
                self.chat_history.remove_widget(record["widget"])
            if record in self.local_vault:
                self.local_vault.remove(record)


class PMApp(App):
    def build(self):
        sm = ScreenManager()
        sm.add_widget(LoginScreen(name='login'))
        sm.add_widget(ChatScreen(name='chat'))
        return sm


if __name__ == '__main__':
    PMApp().run()
