import os
import pandas as pd
import numpy as np
import joblib
from imblearn.over_sampling import SMOTE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
CICIOT23_FILES = ['Merged01.csv', 'Merged02.csv']
CICIOT23_FEATURES = [
    'Header_Length', 'Protocol Type', 'Time_To_Live', 'Rate', 'fin_flag_number',
    'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count',
    'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
    'UDP', 'DHCP', 'ARP', 'ICMP', 'IGMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max',
    'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Variance'
]


def preprocess_data(input_csvs=None, output_csv='balanced_data.csv', sample_frac=0.1, random_state=42):
    input_csvs = input_csvs or CICIOT23_FILES
    dfs = []
    for csv_file in input_csvs:
        print(f'Loading {csv_file} ({sample_frac * 100:.0f}% sample)...')
        path = os.path.join(BASE_DIR, csv_file)
        df_part = pd.read_csv(path).sample(frac=sample_frac, random_state=random_state)
        dfs.append(df_part)

    df = pd.concat(dfs, ignore_index=True)
    print(f'Combined data shape: {df.shape}')

    available_features = [c for c in CICIOT23_FEATURES if c in df.columns]
    df['binary_label'] = df['Label'].apply(
        lambda x: 0 if str(x).strip().lower() in ['benigntraffic', 'normal', 'benign'] else 1
    )

    X = df[available_features].replace([np.inf, -np.inf], np.nan).fillna(0).astype(np.float32)
    y = df['binary_label']

    print('Original label distribution:')
    print(y.value_counts())

    smote = SMOTE(random_state=random_state)
    X_res, y_res = smote.fit_resample(X, y)

    print('Balanced label distribution:')
    print(pd.Series(y_res).value_counts())

    balanced_df = pd.DataFrame(X_res, columns=available_features)
    balanced_df['label'] = y_res
    balanced_path = os.path.join(BASE_DIR, output_csv)
    balanced_df.to_csv(balanced_path, index=False)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(available_features, os.path.join(MODELS_DIR, 'feature_names_ciciot23.pkl'))

    print(f'Saved balanced dataset to {balanced_path}')
    print(f'Saved {len(available_features)} CIC-IoT23 feature names to models/')
    return balanced_df, available_features


if __name__ == '__main__':
    preprocess_data()
