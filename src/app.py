"""
src/app.py
NGFW - Streamlit Dashboard

Interactive Next-Generation Firewall dashboard with ML classification
and automated rule deployment.

Author: Allben Rakgoale
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from traffic_simulator import generate_traffic
from classifier import TrafficClassifier
from rule_engine import RuleEngine


# =========================================================
# Page config
# =========================================================
st.set_page_config(
    page_title="NGFW ML Firewall",
    page_icon="🛡️",
    layout="wide",
)


# =========================================================
# Header
# =========================================================
st.title("🛡️ Allben NGFW - ML Firewall")
st.caption(
    "Next-Generation Firewall with ML-Based Traffic Analysis & Automated Response | "
    "Built by Allben Rakgoale"
)

st.markdown("---")


# =========================================================
# Sidebar
# =========================================================
st.sidebar.header("⚙️ Configuration")

n_flows = st.sidebar.slider(
    "Traffic flows to simulate",
    min_value=500, max_value=5000, value=2000, step=500,
)

confidence_threshold = st.sidebar.slider(
    "Auto-block confidence threshold",
    min_value=0.50, max_value=0.99, value=0.80, step=0.05,
)

rule_format = st.sidebar.radio(
    "Rule format",
    options=["iptables", "pfsense"],
    help="iptables = Linux firewalls | pfsense = BSD-based firewalls",
)

st.sidebar.markdown("---")
st.sidebar.info(
    "🛡️ **NGFW Pipeline:**\n\n"
    "1. Simulate traffic\n"
    "2. Classify with ML\n"
    "3. Generate firewall rules\n"
    "4. Auto-block malicious IPs"
)


# =========================================================
# Run the pipeline (cached)
# =========================================================
@st.cache_data(show_spinner="🌐 Simulating network traffic...")
def run_ngfw_pipeline(n_flows: int):
    df = generate_traffic(n_flows=n_flows)

    classifier = TrafficClassifier()
    metrics = classifier.train(df)
    scored = classifier.predict(df)

    importance = classifier.feature_importance()

    return scored, metrics, importance


scored, metrics, importance = run_ngfw_pipeline(n_flows)


# =========================================================
# Top KPIs
# =========================================================
total_flows = len(scored)
malicious_flows = int(scored["is_malicious"].sum())
malicious_pct = (malicious_flows / total_flows) * 100
model_acc = metrics["accuracy"] * 100

col1, col2, col3, col4 = st.columns(4)
col1.metric("📦 Total Flows", f"{total_flows:,}")
col2.metric("🚨 Malicious Flows", f"{malicious_flows:,}", f"{malicious_pct:.1f}%")
col3.metric("🎯 Model Accuracy", f"{model_acc:.1f}%")
col4.metric("🔬 Features", f"{len(importance)}")

st.markdown("---")


# =========================================================
# Traffic Classification Results
# =========================================================
st.subheader("📊 Traffic Classification Breakdown")

label_counts = scored["predicted_label"].value_counts().reset_index()
label_counts.columns = ["Attack Type", "Count"]

col_left, col_right = st.columns([1, 1])

with col_left:
    fig1 = px.pie(
        label_counts,
        names="Attack Type",
        values="Count",
        color="Attack Type",
        color_discrete_map={
            "normal": "#0E7C7B",
            "port_scan": "#F5821F",
            "ddos": "#DC2626",
            "exfiltration": "#8B5CF6",
        },
        hole=0.4,
    )
    fig1.update_layout(height=350)
    st.plotly_chart(fig1, use_container_width=True)

with col_right:
    fig2 = px.bar(
        label_counts,
        x="Attack Type",
        y="Count",
        color="Attack Type",
        color_discrete_map={
            "normal": "#0E7C7B",
            "port_scan": "#F5821F",
            "ddos": "#DC2626",
            "exfiltration": "#8B5CF6",
        },
        text="Count",
    )
    fig2.update_layout(height=350, showlegend=False, plot_bgcolor="white")
    st.plotly_chart(fig2, use_container_width=True)


# =========================================================
# Feature Importance
# =========================================================
st.subheader("🧠 ML Model - Feature Importance")

fig3 = px.bar(
    importance,
    x="importance",
    y="feature",
    orientation="h",
    color="importance",
    color_continuous_scale="Reds",
)
fig3.update_layout(height=400, plot_bgcolor="white", showlegend=False)
st.plotly_chart(fig3, use_container_width=True)


# =========================================================
# Model Performance
# =========================================================
st.subheader("📈 Model Performance")

col_a, col_b, col_c = st.columns(3)
col_a.metric("🎯 Accuracy", f"{metrics['accuracy']:.2%}")
col_b.metric("⚖️ Macro F1", f"{metrics['macro_f1']:.2%}")
col_c.metric("📊 Weighted F1", f"{metrics['weighted_f1']:.2%}")

with st.expander("🔍 Per-Class Metrics"):
    per_class_df = pd.DataFrame(metrics["per_class"]).T
    per_class_df.columns = ["Precision", "Recall", "F1 Score"]
    per_class_df = per_class_df.round(3)
    st.dataframe(per_class_df, use_container_width=True)


# =========================================================
# Firewall Rule Engine
# =========================================================
st.markdown("---")
st.subheader("🛡️ Automated Firewall Rule Engine")

# Override threshold with sidebar value
RuleEngine.BLOCK_THRESHOLD = confidence_threshold

engine = RuleEngine()
rules = engine.generate_rules(scored, format=rule_format)
summary = engine.get_summary()

# Metrics
col_x, col_y, col_z = st.columns(3)
col_x.metric("🔒 IPs Blocked", summary["total_blocked"])
col_y.metric("📉 Total Rules", len(rules))
col_z.metric(
    "🎯 Avg Confidence",
    f"{summary.get('average_confidence', 0):.2%}",
)

# Blocked by attack type
if summary["by_attack"]:
    st.markdown("#### 🎯 Blocked by Attack Type")
    attack_df = pd.DataFrame(
        summary["by_attack"].items(),
        columns=["Attack Type", "Blocked Count"],
    )
    st.dataframe(attack_df, use_container_width=True, hide_index=True)

# Rules table
if not rules.empty:
    st.markdown(f"#### 📋 Generated {rule_format.upper()} Rules")
    st.dataframe(
        rules[["rule_id", "src_ip", "attack_type", "confidence", "rule"]],
        use_container_width=True,
        hide_index=True,
    )
else:
    st.success("✅ No malicious traffic above confidence threshold - no rules generated.")


# =========================================================
# Live Simulation - Auto-Block in Action
# =========================================================
st.markdown("---")
st.subheader("⚡ Live Attack Simulation")

st.markdown(
    "Click below to simulate a new attack and watch the NGFW respond in real time:"
)

if st.button("🚨 Simulate Attack → Auto-Block"):
    with st.spinner("Simulating attack traffic..."):
        attack_df = generate_traffic(n_flows=100)
        classifier = TrafficClassifier()
        classifier.train(scored)
        attack_scored = classifier.predict(attack_df)

        attack_engine = RuleEngine()
        attack_rules = attack_engine.generate_rules(attack_scored, format=rule_format)

        if not attack_rules.empty:
            st.error(f"🚨 Detected {len(attack_rules)} new threat(s) and blocked them!")
            st.dataframe(
                attack_rules[["src_ip", "attack_type", "confidence", "rule"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("✅ No threats detected in this simulation cycle.")


# =========================================================
# Export Rules
# =========================================================
st.markdown("---")
st.subheader("📥 Export Firewall Rules")

col_dl1, col_dl2 = st.columns(2)

with col_dl1:
    if rule_format == "iptables":
        st.download_button(
            label="⬇️ Download iptables Script (.sh)",
            data=engine.export_iptables_script(),
            file_name="ngfw_rules.sh",
            mime="text/x-sh",
        )
    else:
        st.download_button(
            label="⬇️ Download pfSense Rules (.txt)",
            data=engine.export_pfsense_script(),
            file_name="ngfw_rules_pfsense.txt",
            mime="text/plain",
        )

with col_dl2:
    st.download_button(
        label="⬇️ Download Full Classification Report (CSV)",
        data=scored.to_csv(index=False),
        file_name="ngfw_classification_report.csv",
        mime="text/csv",
    )


# =========================================================
# Footer
# =========================================================
st.markdown("---")
st.caption(
    "🛡️ allben-ngfw-ml-firewall v1.0 | "
    "Built by [Allben Rakgoale](https://github.com/allben09) | "
    "ML: Random Forest (multi-class)"
)
