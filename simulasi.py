# 1) (opsional) buat virtual env
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2) install dependensi
pip install -r requirements.txt

# 3) jalankan app
streamlit run app.py
