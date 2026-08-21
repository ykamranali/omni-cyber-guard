"use client";

import { useState, useRef, useEffect } from "react";
import { Send, User, BrainCircuit, Loader2 } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import { api } from "@/lib/api";

type Message = {
  id: string;
  role: "user" | "agent";
  content: string;
};

export default function AskAgentPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "init",
      role: "agent",
      content: "Hello. I am Omni Security Engineer. I can analyze your network's vulnerabilities, prioritize risks, or provide remediation plans based on our scan data. How can I assist you today?",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const token = useAuthStore((s) => s.accessToken);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMsg: Message = { id: Date.now().toString(), role: "user", content: input };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const data = await api.post<{ response: string }>("/agent/chat", {
        message: userMsg.content,
      });
      
      const agentMsg: Message = {
        id: (Date.now() + 1).toString(),
        role: "agent",
        content: data.response,
      };
      setMessages((prev) => [...prev, agentMsg]);
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { id: Date.now().toString(), role: "agent", content: "Sorry, I am currently offline or encountered an error connecting to the LLM backend." },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-[calc(100vh-4rem)] flex-col gap-4 p-6">
      <div className="flex items-center gap-3 border-b border-border pb-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-secondary">
          <BrainCircuit className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold tracking-tight text-ink">Ask Omni Security Engineer</h1>
          <p className="text-sm text-muted">AI-powered vulnerability analysis and remediation guidance</p>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto rounded-xl border border-border bg-surface p-4 shadow-sm">
        <div className="flex flex-col gap-6">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-4 ${msg.role === "user" ? "flex-row-reverse" : ""}`}
            >
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${
                  msg.role === "user" ? "bg-ink text-surface" : "bg-primary text-white"
                }`}
              >
                {msg.role === "user" ? <User size={16} /> : <BrainCircuit size={16} />}
              </div>
              <div
                className={`max-w-[80%] rounded-2xl px-4 py-3 text-sm ${
                  msg.role === "user"
                    ? "bg-ink text-surface"
                    : "bg-surface-hover text-ink border border-border"
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex gap-4">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-primary text-white">
                <BrainCircuit size={16} />
              </div>
              <div className="max-w-[80%] rounded-2xl bg-surface-hover border border-border px-4 py-3 text-sm text-ink flex items-center gap-2">
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
                Analyzing context...
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
      </div>

      <form onSubmit={handleSubmit} className="flex gap-3">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about vulnerabilities, risks, or remediation..."
          className="flex-1 rounded-xl border border-border bg-surface px-4 py-3 text-sm text-ink placeholder:text-muted focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
          disabled={isLoading}
        />
        <button
          type="submit"
          disabled={!input.trim() || isLoading}
          className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
        >
          <Send size={18} className={isLoading ? "opacity-50" : ""} />
        </button>
      </form>
    </div>
  );
}
