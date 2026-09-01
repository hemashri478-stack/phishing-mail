import pandas as pd

df = pd.read_csv("ai-models/Phising_Testing_Dataset.csv")
print("Target candidate column names and distributions:")
for col in df.columns[-5:]:
    print(f"--- {col} ---")
    print(df[col].value_counts())

print("\nCorrelation with Statistical_report:")
corrs = df.corr()['Statistical_report'].sort_values()
print(corrs)
