import os
from typing import TypedDict, Optional
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END


# Shared Memory State
class AgentState(TypedDict):
    leak_info: dict
    source_code: Optional[str]
    diagnosis: Optional[str]
    fix_suggestion: Optional[str]
    error: Optional[str]


# Define the Nodes
def retrieve_code_node(state: AgentState):
    proc_name = state["leak_info"].get("process_name", "unknown")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

    potential_paths = [
        os.path.join(base_dir, "targets", f"{proc_name}.cpp"),
        os.path.join(base_dir, "targets", "leaker.cpp"),  # Fallback
        f"./targets/{proc_name}.cpp",
    ]

    for path in potential_paths:
        if path and os.path.exists(path):
            with open(path, "r") as f:
                return {"source_code": f.read()}

    return {"error": f"Source code for {proc_name} not found."}


def analyze_leak_node(state: AgentState):
    if state.get("error"):
        return state

    llm = ChatOllama(
        model="llama3.2", base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434")
    )

    prompt = f"""
    Analyze this leak in {state['leak_info']['process_name']}.
    Stack Trace: {state['leak_info']['symbol_path']}
    Source Code:
    {state['source_code']}
    Identify the specific function causing the leak.
    """

    response = llm.invoke(prompt)
    return {"diagnosis": response.content}


def generate_fix_node(state: AgentState):
    if state.get("error"):
        return state

    llm = ChatOllama(
        model="llama3.2", base_url=os.getenv("OLLAMA_HOST", "http://localhost:11434")
    )

    prompt = f"Based on this diagnosis: {state['diagnosis']}, provide the corrected C++ code."

    response = llm.invoke(prompt)

    return {"fix_suggestion": response.content}


# Construct the graph
def create_leak_agent():
    workflow = StateGraph(AgentState)

    workflow.add_node("retrieve_code", retrieve_code_node)
    workflow.add_node("analyze_leak", analyze_leak_node)
    workflow.add_node("generate_fix", generate_fix_node)

    workflow.set_entry_point("retrieve_code")
    workflow.add_edge("retrieve_code", "analyze_leak")
    workflow.add_edge("analyze_leak", "generate_fix")
    workflow.add_edge("generate_fix", END)

    return workflow.compile()
