"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { apiRequest, isUncertainOperationError } from "./api-client";

// Operate: extend the existing TLS list, not a new visual world. A focused
// password/file dialog has one action; import never replaces a live profile.
export function TlsTransferDialog({ profile, onClose, onImported }: {
  profile?: { id: string; name: string };
  onClose: () => void;
  onImported: () => Promise<void>;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [done, setDone] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    dialog.current?.showModal();
    return () => { previous?.focus(); };
  }, []);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const password = String(data.get("password") ?? "");
    setMessage(""); setBusy(true);
    try {
      if (profile) {
        if (password !== data.get("confirmation")) throw new Error("Пароли не совпадают.");
        const result = await apiRequest<{ archive: string; filename: string }>(`/tls-profiles/${encodeURIComponent(profile.id)}/export`, {
          method: "POST", body: JSON.stringify({ password }),
        });
        const bytes = Uint8Array.from(atob(result.archive), char => char.charCodeAt(0));
        const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
        const link = document.createElement("a");
        link.href = url; link.download = "TLS-profile.sbtls";
        document.body.appendChild(link); link.click(); link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 1000);
        setMessage("Архив подготовлен для скачивания. Сохраните пароль отдельно.");
      } else {
        const file = data.get("archive");
        if (!(file instanceof File) || !file.size) throw new Error("Выберите архив TLS-профиля.");
        if (file.size > 1_048_629) throw new Error("Архив слишком большой: максимум 1 МиБ данных профиля.");
        const bytes = new Uint8Array(await file.arrayBuffer());
        let binary = "";
        for (const byte of bytes) binary += String.fromCharCode(byte);
        await apiRequest("/tls-profiles/import", { method: "POST", body: JSON.stringify({ password, archive: btoa(binary) }) });
        setDone(true); form.reset();
        try { await onImported(); }
        catch { setMessage("Профиль импортирован. Обновите страницу, чтобы увидеть его в списке."); return; }
        setMessage("Профиль импортирован и выключен. Проверьте настройки, включите профиль и автопродление; затем назначьте подключениям и примените.");
      }
      form.reset(); setDone(true);
    } catch (error) {
      if (!profile && isUncertainOperationError(error)) {
        setUncertain(true);
        setMessage("Ответ потерян. Обновите список TLS-профилей перед повторным импортом.");
      } else setMessage(error instanceof Error ? error.message : "Не удалось перенести профиль.");
    } finally { setBusy(false); }
  }
  return createPortal(
    <dialog ref={dialog} className="modal tls-transfer-dialog" aria-labelledby="tls-transfer-title"
      onCancel={event => { event.preventDefault(); if (!busy) onClose(); }}>
      <form onSubmit={submit} aria-busy={busy}>
        <h2 id="tls-transfer-title">{profile ? "Экспорт TLS-профиля" : "Импорт TLS-профиля"}</h2>
        {profile ? <p className="tls-transfer-name">{profile.name}</p> : null}
        {!done ? <>
          <p className="field-help">{profile
            ? "Архив содержит приватный ключ и, для ACME, доступ к DNS API. Он защищён паролем."
            : "Будет создан новый выключенный профиль. Существующие подключения не изменятся."}</p>
          {!profile ? <label className="field">Архив профиля
            <input type="file" name="archive" accept=".sbtls" required disabled={busy || uncertain} />
          </label> : null}
          <label className="field">Пароль архива
            <input type="password" name="password" autoComplete={profile ? "new-password" : "off"} minLength={12} maxLength={256} required disabled={busy || uncertain} />
            {profile ? <span className="field-help">Не менее 12 символов.</span> : null}
          </label>
          {profile ? <label className="field">Повторите пароль
            <input type="password" name="confirmation" autoComplete="new-password" minLength={12} maxLength={256} required disabled={busy} />
          </label> : null}
        </> : null}
        {message ? <p role={done ? "status" : "alert"} className={done ? "field-help" : "form-error"}>{message}</p> : null}
        <div className="modal-actions">
          <button type="button" className="button button-secondary" disabled={busy} onClick={onClose}>{done || uncertain ? "Закрыть" : "Отмена"}</button>
          {!done ? <button type="submit" className="button button-primary" disabled={busy || uncertain}>
            {busy ? "Выполняется…" : profile ? "Скачать архив" : "Импортировать"}
          </button> : null}
        </div>
      </form>
    </dialog>, document.body,
  );
}
