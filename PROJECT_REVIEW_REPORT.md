# IDS with Machine Learning - Complete Project Review Report

## 1. Project Title
Intrusion Detection System (IDS) with Machine Learning using CIC-IoT23 and Live Network Monitoring

---

## 2. Project Objective
The goal of this project is to detect malicious network activity using a machine learning based IDS. The system supports two major flows:

1. Offline CSV-based traffic analysis
2. Live packet capture and real-time threat detection

The project is trained on the CIC-IoT23 dataset and uses XGBoost as the deployed prediction model, while Random Forest and Decision Tree are trained and evaluated for comparison.

---

## 3. Dataset Used
### 3.1 Dataset Name
CIC-IoT23 Dataset

### 3.2 Dataset Files Used in This Project
- `Merged01.csv`
- `Merged02.csv`

### 3.3 What the Dataset Contains
The dataset contains flow-level network traffic records. Each row represents one traffic flow and contains numeric features that describe packet behavior, protocol usage, traffic statistics, and timing patterns.

Examples of the feature types used in our project:
- Packet/header features: `Header_Length`, `Time_To_Live`, `Rate`
- TCP flag features: `syn_flag_number`, `ack_flag_number`, `rst_flag_number`, `psh_flag_number`
- Count features: `ack_count`, `syn_count`, `fin_count`, `rst_count`
- Protocol indicators: `HTTP`, `HTTPS`, `DNS`, `SSH`, `TCP`, `UDP`, `ICMP`, `ARP`, `DHCP`
- Statistical features: `Tot sum`, `Min`, `Max`, `AVG`, `Std`, `Tot size`, `IAT`, `Number`, `Variance`

The original dataset has detailed attack labels, but in this project those labels are converted into a binary task:
- `0 = Benign`
- `1 = Attack`

---

## 4. Main Dataset Problem
The major problem in the dataset is **class imbalance**.

In the sampled CIC-IoT23 data used for our latest training run:
- Total sampled rows before balancing: `146,089`
- Attack rows: `142,679`
- Benign rows: `3,410`

This means the model sees many more attack rows than normal rows. If trained directly on this distribution, the model may become biased toward predicting `Attack` more often and may not learn `Benign` traffic properly.

---

## 5. Our Solution to the Dataset Problem
We solve this imbalance using **SMOTE (Synthetic Minority Over-sampling Technique)**.

### 5.1 What SMOTE Does
SMOTE adds synthetic minority-class rows. In our case, it generates additional `Benign` examples so that both classes become balanced.

### 5.2 Important Clarification
SMOTE changes the **number of rows**, not the **number of columns**.

So:
- The feature count remains the same: `39`
- The row count increases after balancing

### 5.3 Why We Add Rows Instead of Only Reducing Features
Reducing features and balancing rows solve different problems:
- Feature reduction removes unnecessary columns and reduces noise
- Row balancing fixes class imbalance

In our project, the main problem was not too many columns, but too few `Benign` examples compared to `Attack` examples. That is why balancing helps more directly.

---

## 6. Features Used in Training
This project uses **39 selected CIC-IoT23 numeric flow features**.

### 6.1 Why 39 Features Are Still Used After Balancing
The balanced dataset still uses the same 39 features because balancing does not alter the feature structure. It only adjusts class representation by creating synthetic minority-class rows.

### 6.2 Selected Feature Count
- Selected features used for training: `39`
- Balanced dataset feature count: `39`

---

## 7. Data Size Before and After Balancing
### 7.1 Before Balancing
- Total sampled rows: `146,089`
- Features used: `39`
- Class distribution:
  - Attack: `142,679`
  - Benign: `3,410`

### 7.2 After Balancing
- Total balanced rows: `285,358`
- Features used: `39`
- Balanced distribution:
  - Attack: `142,679`
  - Benign: `142,679`

---

## 8. Training and Testing Split Used
From the balanced dataset:
- Training rows: `228,286`
- Testing rows: `57,072`
- Train-test ratio: `80:20`

### 8.1 Sample Fraction Used
This project does **not** use 100% of the raw merged files in the latest saved run.

The current saved training run uses:
- `10%` sample from `Merged01.csv`
- `10%` sample from `Merged02.csv`

That sampled data is then balanced using SMOTE.

---

## 9. Models Trained
We train three algorithms:
- Random Forest
- Decision Tree
- XGBoost

### 9.1 Why Only XGBoost `.pkl` Is Visible
Only the XGBoost model is saved as the production model file because it achieved the best accuracy in our setup.

Random Forest and Decision Tree are still trained and evaluated, but they are used only for comparison and their metrics are stored in the JSON metrics file.

### 9.2 Saved Model Files
- XGBoost model: `models/xgb_model_ciciot23.pkl`
- Feature names: `models/feature_names_ciciot23.pkl`
- Metrics: `models/model_metrics_ciciot23.json`

---

## 10. How the Model Is Trained
### 10.1 Training Flow
1. Load `Merged01.csv` and `Merged02.csv`
2. Sample 10% of the rows from each file
3. Select the 39 CIC-IoT23 numeric flow features
4. Convert detailed labels into binary labels: `Benign` vs `Attack`
5. Replace missing and infinite values
6. Apply SMOTE to balance the rows
7. Split into training and testing sets
8. Train Random Forest, Decision Tree, and XGBoost
9. Evaluate accuracy, precision, recall, and F1-score
10. Save XGBoost as the deployed model

### 10.2 What XGBoost Does
XGBoost is a gradient-boosted tree model. Instead of building just one tree, it builds many trees sequentially. Each new tree tries to correct the errors made by the previous trees.

Why it performs well:
- Strong on structured tabular data
- Handles non-linear patterns well
- Learns feature interactions effectively
- Usually gives better accuracy than a single Decision Tree

---

## 11. Metrics Used
The project evaluates the models using:
- Accuracy
- Precision
- Recall
- F1-score

### 11.1 Meaning of Each Metric
**Accuracy**
- Overall percentage of correct predictions
- Formula: `(TP + TN) / Total`

**Precision**
- Of all rows predicted as attack, how many are actually attack
- High precision means fewer false alarms

**Recall**
- Of all actual attack rows, how many the model successfully detects
- High recall means fewer missed attacks

**F1-score**
- Harmonic mean of precision and recall
- Useful when both false alarms and missed attacks matter

---

## 12. Current Project Results
The latest saved metrics are:

| Model | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| Random Forest | 99.56% | 99.84% | 99.28% | 99.56% |
| Decision Tree | 99.32% | 99.82% | 98.83% | 99.32% |
| XGBoost | 99.59% | 99.77% | 99.41% | 99.59% |

### 12.1 Best Model
- Best saved model: `XGBoost`
- Saved deployment accuracy: `99.59%`

---

## 13. Comparison with Paper-Reported CIC-IoT23 Results
The research paper used as the technical base reports lower CIC-IoT23 scores for the classical models than our current prototype.

### 13.1 Paper-Reported CIC-IoT23 Reference Scores
| Model | Paper score on CIC-IoT23 |
|---|---:|
| Random Forest | 93.59% |
| Decision Tree | 91.54% |

### 13.2 Our Current Project Scores
| Model | Our score |
|---|---:|
| Random Forest | 99.56% |
| Decision Tree | 99.32% |
| XGBoost | 99.59% |

### 13.3 Why Our Accuracy Is Higher
Our project currently gives higher scores because the setup is different and easier in some important ways:
- We convert the task into **binary classification**: `Benign` vs `Attack`
- We use a **balanced dataset** created with SMOTE
- We train on a selected **39-feature** subset aligned with our app pipeline
- We use **XGBoost**, which is a stronger model than a single Decision Tree
- We use only a **10% sample** from each merged file for the saved run

### 13.4 Important Fairness Note
These results are real outputs from our code, but they are **not a strict apples-to-apples comparison** with the paper because:
- the paper and our current prototype do not use the exact same label setup
- our current project uses a balanced binary setup
- the current preprocessing pipeline applies SMOTE before train-test split, which can make results look optimistic

So the safest academic statement is:
> Our prototype achieved very high scores on a balanced binary CIC-IoT23 setup, with XGBoost performing best.

---

## 14. Live Monitoring Explanation
### 14.1 How Live Monitoring Works
The live monitoring part captures packets in real time using **Scapy**. It listens on the available network interfaces, groups packets into flows, converts those flows into numeric CIC-IoT23-style features, and then sends those features to the trained XGBoost model.

### 14.2 Steps in Live Monitoring
1. Capture packets from the system interfaces
2. Group packets into flows
3. Extract numeric features from each flow
4. Pass those features to the trained model
5. Get prediction and probability score
6. Combine ML output with heuristic rules
7. Display final detection result in the UI

### 14.3 Named Attack Types in Live Monitoring
The live system currently uses these categories:
- Normal
- Port Scanning
- Brute Force
- Service Exploit
- DDoS Attack
- Suspicious Activity

### 14.4 What Happens If Another Attack Occurs
If the traffic does not strongly match one of the named attack categories, the system marks it as:
- `Suspicious Activity`

This avoids forcing an incorrect specific label.

### 14.5 Does Live Monitoring Use the Trained Model?
Yes. The live-monitoring flow extracts the same style of numeric features used in training and sends them to the loaded XGBoost model.

So live monitoring uses:
- trained feature list
- trained XGBoost model
- heuristic support rules

---

## 15. How Confidence Score Is Calculated
The confidence score mainly comes from the XGBoost probability output.

The code uses model probability from:
- `predict_proba()`

Interpretation:
- If prediction is `Attack`, confidence is based on attack probability
- If prediction is `Normal`, confidence is based on normal probability

In live monitoring, this confidence is further supported by heuristic agreement.

---

## 16. Code Overview and Important Functions
### 16.1 Preprocessing Code
File: [preprocess.py](D:/VISHWAK%20AMRITA/4th%20Sem/System%20Security/CAPSTONE_Project/preprocess.py)

Important parts:
- `CICIOT23_FEATURES` at line `10`
  - defines the 39 selected features
- `preprocess_data()` at line `20`
  - loads sampled CIC-IoT23 data
  - maps labels into binary labels
  - applies SMOTE
  - saves `balanced_data.csv`
- `smote = SMOTE(...)` at line `43`
  - creates the balanced class distribution
- `balanced_df.to_csv(...)` at line `52`
  - saves the balanced dataset

### 16.2 Model Training Code
File: [train.py](D:/VISHWAK%20AMRITA/4th%20Sem/System%20Security/CAPSTONE_Project/train.py)

Important parts:
- `score_model()` at line `15`
  - calculates accuracy, precision, recall, and F1-score
- `train_model()` at line `26`
  - runs the complete training pipeline
- `XGBClassifier` imported at line `4`
- `RandomForestClassifier` imported at line `5`
- `DecisionTreeClassifier` imported at line `6`
- `train_test_split` imported at line `7`

### 16.3 Main App Code
File: [app.py](D:/VISHWAK%20AMRITA/4th%20Sem/System%20Security/CAPSTONE_Project/app.py)

Important parts:
- `CICIOT23_FEATURES` at line `93`
  - active CIC-IoT23 feature list for the app
- `classify_attack_type()` at line `962`
  - maps prediction to attack categories for reports/upload
- `build_results()` at line `996`
  - creates result rows and confidence values
- `/api/train` route at line `1159`
  - training API used from the UI

### 16.4 Live Monitoring Functions
File: [app.py](D:/VISHWAK%20AMRITA/4th%20Sem/System%20Security/CAPSTONE_Project/app.py)

Important functions:
- `get_network_info()` at line `233`
  - detects interfaces and host IPs
- `packet_flow_key()` at line `343`
  - groups packets into flows
- `infer_live_attack_type()` at line `381`
  - infers likely live attack category
- `combine_live_verdict()` at line `403`
  - combines ML and heuristic decisions
- `extract_flow_features()` at line `531`
  - converts live flows into numeric features
- `heuristic_analysis()` at line `607`
  - rule-based live detection support
- `/live-monitoring` route at line `1357`
  - live monitoring page
- `/api/live-poll` route at line `1391`
  - live update endpoint

---

## 17. Why Random Forest and Decision Tree Still Matter
Even though only XGBoost is saved as the production `.pkl` model, Random Forest and Decision Tree are still important because they:
- provide baseline comparison
- help show that the project tested multiple ML algorithms
- make the review more complete and academically stronger

---

## 18. Limitations to Mention Honestly During Review
These points should be mentioned clearly if asked:
- The current project uses binary `Benign` vs `Attack` classification
- The current evaluation setup is not identical to the paper
- SMOTE is applied before train-test split in the present pipeline, which can make metrics optimistic
- Live monitoring supports a limited set of named attack categories, with other cases going to `Suspicious Activity`

---

## 19. Short Viva Answers
### 19.1 What does the dataset contain?
It contains network flow records with numeric traffic features and traffic labels.

### 19.2 What is the main problem in the dataset?
Class imbalance: attack rows are much higher than benign rows.

### 19.3 What solution did we use?
We balanced the sampled dataset using SMOTE.

### 19.4 Did balancing change the 39 features?
No. Balancing changes row count, not column count.

### 19.5 Why is XGBoost used as final model?
Because it achieved the best accuracy and overall performance in our setup.

### 19.6 Does live monitoring use the trained model?
Yes. It extracts the same style of numeric features and uses the saved XGBoost model for prediction.

### 19.7 Why are our scores higher than the paper?
Because our current setup is balanced, binary, and easier than a direct paper-style multi-class comparison.

---

## 20. Space for Code Snippets
### 20.1 Preprocessing Code Snippet
```python
# Paste preprocessing code snippet here
```

### 20.2 Training Code Snippet
```python
# Paste training code snippet here
```

### 20.3 Live Monitoring Code Snippet
```python
# Paste live monitoring code snippet here
```

---

## 21. Space for Results Screenshots
### 21.1 Training Results Screenshot
- Paste screenshot here

### 21.2 Upload Results Screenshot
- Paste screenshot here

### 21.3 Live Monitoring Screenshot
- Paste screenshot here

### 21.4 Reports Screenshot
- Paste screenshot here

---

## 22. Final Conclusion
This project builds a practical IDS around the CIC-IoT23 dataset using selected flow-level features, SMOTE-based balancing, and XGBoost-based prediction. The system supports both offline CSV analysis and live network monitoring. In the current saved run, XGBoost achieved the best performance, while Random Forest and Decision Tree were also trained for comparison. The project demonstrates strong detection performance, but the reported scores should be presented honestly as results from a balanced binary CIC-IoT23 setup.
