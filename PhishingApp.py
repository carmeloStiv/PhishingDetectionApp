"""Streamlit front-end (kept so an existing Streamlit deployment of this repository keeps working).

    streamlit run PhishingApp.py

It uses exactly the same detection engine as the main web application
(`uvicorn server.app:app`). The main application is the recommended way to run
the project: it adds the full interface, history, feedback, rate limiting and
security headers, none of which Streamlit provides.
"""
import streamlit as st

from phishdetect.config import Settings
from phishdetect.engine import Engine, InputError

SOURCE = {"threat_intel": "Threat intelligence", "heuristic": "Rule", "page": "Page content", "ml": "ML model",
          "reputation": "Reputation"}


@st.cache_resource
def get_engine() -> Engine:
    return Engine(Settings())


st.set_page_config(page_title="Phishing Detector", layout="centered")
st.title("Phishing Detector")
st.write("Paste a web address, an e-mail or a message. You get a verdict, the evidence behind it and what to do next.")

text = st.text_area("Web address or message", height=160, max_chars=50_000,
                    placeholder="https://example.com/login  or the full text of an e-mail")
mode = st.radio("What are you checking?", ["auto", "url", "message"], horizontal=True,
                format_func={"auto": "Auto-detect", "url": "Web address", "message": "E-mail or message"}.get)

if st.button("Analyse", type="primary"):
    try:
        with st.spinner("Analysing..."):
            report = get_engine().analyse(text, mode)
    except InputError as exc:
        st.warning(str(exc))
    else:
        show = {"likely_phishing": st.error, "suspicious": st.warning, "likely_safe": st.success, "unable_to_determine": st.info}
        show[report["classification"]](f"**{report['label']}** - risk score {report['risk_score']}/100, "
                                       f"confidence {report['confidence']['level']}")
        st.caption(report["subject"])
        st.write(report["summary"])
        st.subheader("What to do")
        for rec in report["recommendations"]:
            st.markdown(f"- {rec}")
        risk = [i for i in report["indicators"] if i["weight"] > 0]
        other = [i for i in report["indicators"] if i["weight"] <= 0]
        st.subheader(f"Risk indicators ({len(risk)})")
        if not risk:
            st.write("None found." if report["classification"] == "likely_safe"
                     else "None found. That alone does not make it safe.")
        for ind in risk + other:
            if ind is (other[0] if other else None):
                st.subheader("Supporting and neutral observations")
            with st.expander(f"{ind['severity'].upper()} - {ind['title']}  [{SOURCE.get(ind['source'], ind['source'])}]"):
                st.text(ind["evidence"])          # st.text never renders HTML or links
                st.write(ind["explanation"])
        with st.expander("Checks performed"):
            st.table([{"Check": c["name"], "Status": c["status"], "Detail": c["detail"]} for c in report["checks"]])
        st.download_button("Download report (JSON)", data=__import__("json").dumps(report, indent=2),
                           file_name=f"phishing-report-{report['id'][:8]}.json", mime="application/json")
