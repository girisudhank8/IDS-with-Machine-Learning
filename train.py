import json
import os
import joblib
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from preprocess import preprocess_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')


def score_model(model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    return {
        'accuracy': round(accuracy_score(y_test, y_pred) * 100, 2),
        'precision': round(precision_score(y_test, y_pred) * 100, 2),
        'recall': round(recall_score(y_test, y_pred) * 100, 2),
        'f1_score': round(f1_score(y_test, y_pred) * 100, 2),
    }


def train_model(sample_frac=0.1):
    print('Creating balanced CIC-IoT23 dataset...')
    balanced_df, feature_names = preprocess_data(output_csv='balanced_data.csv', sample_frac=sample_frac)

    X = balanced_df.drop('label', axis=1)
    y = balanced_df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    rf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    dt = DecisionTreeClassifier(random_state=42, max_depth=14, min_samples_split=8)
    xgb = XGBClassifier(
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=4,
    )

    print('Training Random Forest...')
    rf_metrics = score_model(rf, X_train, X_test, y_train, y_test)
    print('Training Decision Tree...')
    dt_metrics = score_model(dt, X_train, X_test, y_train, y_test)
    print('Training XGBoost...')
    xgb_metrics = score_model(xgb, X_train, X_test, y_train, y_test)

    os.makedirs(MODELS_DIR, exist_ok=True)
    joblib.dump(xgb, os.path.join(MODELS_DIR, 'xgb_model_ciciot23.pkl'))
    joblib.dump(feature_names, os.path.join(MODELS_DIR, 'feature_names_ciciot23.pkl'))

    metrics = {
        'random_forest': rf_metrics,
        'decision_tree': dt_metrics,
        'xgboost': xgb_metrics,
        'meta': {
            'dataset': 'CIC-IoT23 Dataset',
            'dataset_key': 'ciciot23',
            'features': len(feature_names),
            'train_samples': len(X_train),
            'test_samples': len(X_test),
            'balanced_samples': len(balanced_df),
            'sample_fraction': sample_frac,
            'balancing_method': 'SMOTE',
        }
    }
    with open(os.path.join(MODELS_DIR, 'model_metrics_ciciot23.json'), 'w') as f:
        json.dump(metrics, f, indent=2)
    with open(os.path.join(MODELS_DIR, 'active_model.json'), 'w') as f:
        json.dump({'dataset_key': 'ciciot23'}, f)

    print('Saved CIC-IoT23 model artifacts to models/')
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == '__main__':
    train_model()
