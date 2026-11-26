import os
from .leak_agent import create_leak_agent


def diagnosis_leak(leak_info):
    agent = create_leak_agent()

    print(f"Agent starting analysis for PID {leak_info['pid']}...")
    result = agent.invoke({"leak_info": leak_info})

    if result.get("error"):
        print(f"Agent Error: {result['error']}")
        return f"# AI AGENT LEAK REPORT\nERROR: {result['error']}"

    diagnosis = result.get("diagnosis", "No diagnosis generated.")
    fix = result.get("fix_suggestion", "No fix suggested.")
    report = f"""
    # AI AGENT LEAK REPORT
    {diagnosis}
    
    ## SUGGESTED FIX
    {fix}
    """

    report_path = f"./data/reports/leak_{leak_info['pid']}.md"
    os.makedirs("./data/reports", exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)

    return report
