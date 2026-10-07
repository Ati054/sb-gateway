"use client";

import { useCallback, useEffect, useState } from "react";
import { GatewayApiError, getContainerMemoryStatus, updateContainerMemory, type JsonObject } from "./api-client";
import { memoryMiB, validMemoryMiB } from "./container-memory-settings";
import { useLanguage } from "./i18n";

export function ContainerMemory({ container, onChanged }: { container: JsonObject; onChanged: () => Promise<void> }) {
  const { tr } = useLanguage();
  const [high, setHigh] = useState(() => memoryMiB(container.memory_high));
  const [maximum, setMaximum] = useState(() => memoryMiB(container.memory_max));
  const [actual, setActual] = useState(container);
  const [confirmed, setConfirmed] = useState(false);
  const [pending, setPending] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);
  const [available, setAvailable] = useState(false);
  const load = useCallback(async () => {
    const result = await getContainerMemoryStatus();
    const live = (result.container ?? {}) as JsonObject;
    const operation = (result.operation ?? {}) as JsonObject;
    setActual(live);
    setAvailable(live.inventory_available === true);
    setPending(operation.pending === true);
    if (operation.state === "completed") {
      setMessage(tr("Лимиты подтверждены RouterOS, панель восстановлена."));
      setFailed(false);
    } else if (operation.state === "unconfirmed") {
      setMessage(tr("Изменение не подтверждено. Проверьте контейнер и журнал RouterOS."));
      setFailed(true);
    }
    return live;
  }, [tr]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (!active) return;
      void load().then((live) => {
        if (active) { setHigh(memoryMiB(live.memory_high)); setMaximum(memoryMiB(live.memory_max)); }
      }).catch(() => {
        if (active) { setAvailable(false); setFailed(true); setMessage(tr("Не удалось получить текущие лимиты RouterOS.")); }
      });
    });
    return () => { active = false; };
  }, [load, tr]);
  useEffect(() => {
    if (!pending) return;
    let active = true;
    let timer: number;
    async function poll() {
      try { await load(); } catch { setAvailable(false); }
      if (active) timer = window.setTimeout(() => void poll(), 5000);
    }
    timer = window.setTimeout(() => void poll(), 5000);
    return () => { active = false; window.clearTimeout(timer); };
  }, [pending, load]);
  const changed = high !== memoryMiB(actual.memory_high) || maximum !== memoryMiB(actual.memory_max);
  async function save() {
    setBusy(true); setFailed(false); setMessage("");
    try {
      const result = await updateContainerMemory({ memory_high_mib: Number(high), memory_max_mib: Number(maximum), confirmation: "ПЕРЕЗАПУСТИТЬ" });
      const operation = (result.operation ?? {}) as JsonObject;
      setPending(operation.pending === true);
      setMessage(operation.pending === true ? tr("Ожидание перезапуска и подтверждения RouterOS…") : tr("Лимиты не изменились."));
      setConfirmed(false);
      void onChanged().catch(() => {});
    } catch (error) {
      setFailed(true);
      setMessage(error instanceof Error ? error.message : tr("Не удалось изменить лимиты памяти."));
      if (error instanceof GatewayApiError && ["container_memory_schedule_unconfirmed", "upstream_unavailable", "timeout", "unreachable"].includes(error.code ?? "")) setPending(true);
    } finally { setBusy(false); }
  }
  return <div className="container-memory-fields">
    <div className="memory-limits-grid">
      <label className="field">{tr("Мягкий порог, МиБ (memory-high)")}<input type="number" min="16" max="8192" step="1" value={high} disabled={busy || pending || !available} onChange={(event) => { setHigh(event.target.value); setConfirmed(false); }} /></label>
      <label className="field">{tr("Жёсткий лимит, МиБ (memory-max)")}<input type="number" min="16" max="8192" step="1" value={maximum} disabled={busy || pending || !available} onChange={(event) => { setMaximum(event.target.value); setConfirmed(false); }} /></label>
    </div>
    {changed && !validMemoryMiB(high, maximum) ? <p className="mini-notice" role="alert">{tr("Укажите целые значения: 16 ≤ memory-high ≤ memory-max ≤ 8192 МиБ.")}</p> : null}
    <label className="memory-confirmation"><input type="checkbox" checked={confirmed} disabled={busy || pending || !changed} onChange={(event) => setConfirmed(event.target.checked)} />{tr("Подтверждаю перезапуск контейнера")}</label>
    <button className="button button-secondary" type="button" disabled={busy || pending || !confirmed || !changed || !validMemoryMiB(high, maximum) || !available} onClick={() => void save()}>{pending || busy ? tr("Применяется…") : tr("Применить и перезапустить")}</button>
    {message ? <p className="mini-notice" role={failed ? "alert" : "status"}>{message}</p> : null}
  </div>;
}
