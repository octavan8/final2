import streamlit as st
from app1 import show_RF
from app2 import show_IRF
import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
import re
from PIL import Image
from urllib.parse import urlparse
from tld import get_tld
import os.path

page = st.sidebar.selectbox("Pilih Metode", ("Improve Random Forest", "Random Forest"))
if page == "Improve Random Forest":
    show_IRF()
else:
    show_RF()