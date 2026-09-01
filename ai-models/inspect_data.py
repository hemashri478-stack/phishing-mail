import pandas as pd

df = pd.read_csv("ai-models/Phising_Testing_Dataset.csv")
print("Shape:", df.shape)
print("Columns:", list(df.columns))
print("\nFirst 3 rows:")
print(df.head(3))
print("\nSummary of all columns:")
print(df.info())
print("\nUnique values in each column:")
for col in df.columns:
    print(f"{col}: {df[col].unique()[:5]}")
