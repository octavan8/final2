import streamlit as st
from app1 import show_RF
from app2 import show_IRF

page = st.sidebar.selectbox("Pilih Metode", ("Improve Random Forest", "Random Forest"))
if page == "Improve Random Forest":
    show_IRF()
else:
    show_RF()