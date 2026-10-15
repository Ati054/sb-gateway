"use client";

import { AcmeFields, useAcmeProfile } from "../acme-fields";
import { JsonObject, createCollectionItem, deleteCollectionItem, updateCollectionItem } from "../api-client";
import { useLanguage } from "../i18n";
import { TlsTransferDialog } from "../tls-transfer";
import { Toggle, asObject, asObjectList, asText, cdnDeploymentsForTransport, entityIdFromName, errorMessage, itemName, tlsProfileExpiry, transportKindLabel } from "./shared";
import { FormEvent, useEffect, useRef, useState } from "react";

export function TlsProfileDialog({
  profileId,
  onClose,
  onSaved,
  config,
}: {
  profileId?: string;
  onClose: () => void;
  onSaved: () => Promise<void>;
  config: JsonObject;
}) {
  const { locale, tr } = useLanguage();
  const certificateRef = useRef<HTMLInputElement>(null);
  const privateKeyRef = useRef<HTMLInputElement>(null);
  const [exportOpen, setExportOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");
  const [deleteArmed, setDeleteArmed] = useState(false);
  const [workingId, setWorkingId] = useState(profileId);
  const profiles = asObjectList(config.tls_profiles);
  const existing = profiles.find((profile) => asText(profile.id, "") === workingId) ?? {};
  const savedCertificateMode = asText(existing.certificate_source, "") ||
    (asText(existing.certificate_secret_ref, "").endsWith("/acme-bundle.pem") ? "acme" : "manual");
  const [localCAServerName, setLocalCAServerName] = useState(asText(existing.local_ca_server_name, ""));
  const acme = useAcmeProfile(workingId, savedCertificateMode);
  const refreshedCertificate = useRef("");
  const issuedFingerprint = asText(asObject(acme.status.metadata).fingerprint_sha256, "") || asText(asObject(acme.status.metadata).not_after, "");
  useEffect(() => {
    if (acme.status.state !== "issued" || !issuedFingerprint || refreshedCertificate.current === issuedFingerprint) return;
    refreshedCertificate.current = issuedFingerprint;
    void onSaved().catch(() => { refreshedCertificate.current = ""; });
  }, [acme.status.state, issuedFingerprint, onSaved]);
  const editing = Boolean(profileId);
  const usedByLabels = asObjectList(config.transports).flatMap((transport) => {
    const kind = asText(transport.kind, "");
    if (["ws", "grpc", "httpupgrade", "xhttp"].includes(kind)) {
      return cdnDeploymentsForTransport(transport)
        .filter((deployment) =>
          asText(
            deployment.tls_profile_id,
            asText(transport.tls_profile_id, ""),
          ) === profileId,
        )
        .map(
          (deployment) =>
            `${transportKindLabel(kind)} / ${asText(deployment.display_name, "CDN")}`,
        );
    }
    return asText(transport.tls_profile_id, "") === profileId
      ? [transportKindLabel(kind)]
      : [];
  });
  const usedByPublicIngress =
    asText(asObject(config.ingress).tls_profile_id, "") === profileId;
  if (usedByPublicIngress) usedByLabels.unshift("Status / health");
  const usedBySubscriptionIngress =
    asText(asObject(config.ingress).subscription_tls_profile_id, "") === profileId;
  if (usedBySubscriptionIngress) usedByLabels.unshift(tr("Клиентская подписка"));
  const pairReady = Boolean(
    asText(existing.certificate_secret_ref, "") &&
      asText(existing.private_key_secret_ref, ""),
  );
  const normalizedLocalCAServerName = localCAServerName.trim().toLowerCase().replace(/\.+$/, "");
  const localCAPairReady = pairReady && savedCertificateMode === "local-ca" &&
    normalizedLocalCAServerName === asText(existing.local_ca_server_name, "").toLowerCase().replace(/\.+$/, "");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = new FormData(event.currentTarget);
      const displayName = String(data.get("display_name") ?? "").trim();
      if (!displayName) throw new Error(tr("Введите название TLS-профиля."));
      const id = workingId ?? entityIdFromName(
        displayName,
        new Set(profiles.map((profile) => asText(profile.id, ""))),
        "tls-profile",
      );
      const certificateFile = acme.mode === "manual" ? certificateRef.current?.files?.[0] ?? null : null;
      const privateKeyFile = acme.mode === "manual" ? privateKeyRef.current?.files?.[0] ?? null : null;
      const certificate = certificateFile ? (await certificateFile.text()).trim() : "";
      const privateKey = privateKeyFile ? (await privateKeyFile.text()).trim() : "";
      if (Boolean(certificate) !== Boolean(privateKey)) {
        throw new Error(tr("Сертификат и private key нужно загрузить одной парой."));
      }
      if (certificate && !certificate.includes("BEGIN CERTIFICATE")) {
        throw new Error(tr("Сертификат должен быть в формате PEM."));
      }
      if (privateKey && !privateKey.includes("PRIVATE KEY")) {
        throw new Error(tr("Private key должен быть в формате PEM."));
      }
      const submitter = (event.nativeEvent as SubmitEvent).submitter;
      const regenerateLocalCA = submitter?.getAttribute("data-generate-local-ca") === "true";
      const generateLocalCA = acme.mode === "local-ca" && (
        regenerateLocalCA || !localCAPairReady
      );
      const item: JsonObject = {
        ...existing,
        id,
        display_name: displayName,
        enabled: data.get("enabled") === "on",
        certificate_source: acme.mode,
        ...(acme.mode === "local-ca"
          ? { local_ca_server_name: normalizedLocalCAServerName, generate_local_ca: generateLocalCA }
          : {}),
        ...(certificate
          ? { secret_values: { certificate, private_key: privateKey } }
          : {}),
      };
      // The server retains the latest pair atomically, including a certificate
      // issued after this form was opened. A manual upload still replaces it.
      delete item.certificate_secret_ref;
      delete item.private_key_secret_ref;
      delete item.certificate_metadata;
      if (workingId) {
        await updateCollectionItem("tls-profiles", id, item);
      } else {
        await createCollectionItem("tls-profiles", item);
        setWorkingId(id);
      }
      const issue = submitter?.getAttribute("data-issue") === "true";
      await acme.save(id, issue);
      await onSaved();
      setSaved(acme.mode !== "acme");
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={() => { if (!exportOpen) onClose(); }}>
      <section className="modal modal-wide" role="dialog" aria-modal="true" aria-labelledby="tls-profile-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="modal-close" type="button" onClick={onClose} aria-label={tr("Закрыть")}>×</button>
        {saved ? (
          <div className="modal-success" role="status">
            <span>✓</span>
            <h2 id="tls-profile-title">{tr("TLS-профиль сохранён")}</h2>
            <p>{tr("Пара хранится в SecretStore. Связанные транспорты получат изменения после Apply.")}</p>
            <button className="button button-primary" type="button" onClick={onClose}>{tr("Готово")}</button>
          </div>
        ) : (
          <form onSubmit={submit}>
            <p className="eyebrow">{tr("Сертификат подключений")}</p>
            <h2 id="tls-profile-title">{editing ? tr("Настроить · {value1}", { value1: itemName(existing) }) : tr("Добавить TLS-профиль")}</h2>
            <div className="form-grid">
              <label className="field">
                 {tr("Имя профиля")} <input name="display_name" defaultValue={asText(existing.display_name, "")} placeholder={tr("Основной")} maxLength={96} required />
              </label>
              <label className="field">{tr("Сертификат")} <select value={acme.mode} disabled={!acme.loaded} onChange={(event) => acme.setMode(event.target.value)}>
                  <option value="manual">{tr("Загрузить файлы")}</option>
                  <option value="acme">{tr("Автоматически · ACME")}</option>
                  <option value="local-ca">{tr("Локальный CA · TLS Pin")}</option>
                </select>
              </label>
              {acme.mode === "acme" ? <AcmeFields model={acme} /> : acme.mode === "local-ca" ? <>
              <label className="field form-span">
                {tr("SNI сертификата")}
                <input
                  name="local_ca_server_name"
                  type="text"
                  inputMode="url"
                  value={localCAServerName}
                  onChange={(event) => setLocalCAServerName(event.target.value)}
                  placeholder="www.example.com"
                  maxLength={253}
                  autoComplete="off"
                  required
                />
                <small>{tr("Root CA и leaf создаются на шлюзе. Срок действия leaf — 10 лет.")}</small>
              </label>
              <aside className="notice notice-neutral form-span">
                <span className="notice-icon">{localCAPairReady ? "✓" : "!"}</span>
                <div>
                  <strong>{localCAPairReady ? tr("Локальный сертификат настроен") : tr("Сертификат будет создан при сохранении")}</strong>
                  {localCAPairReady ? <small>{tr("Действует до:")} {tlsProfileExpiry(existing, locale)}</small> : null}
                </div>
              </aside>
              </> : <>
              <label className="field">
                 {tr("TLS-сертификат · PEM")} <input ref={certificateRef} name="certificate" type="file" accept=".pem,.crt,.cer,application/x-pem-file" />
              </label>
              <label className="field">
                 {tr("Соответствующий private key · PEM")} <input ref={privateKeyRef} name="private_key" type="file" accept=".pem,.key,application/x-pem-file" />
              </label>
              <aside className="notice notice-neutral form-span">
                <span className="notice-icon">{pairReady ? "✓" : "!"}</span>
                <div>
                  <strong>{pairReady ? tr("TLS-пара настроена") : tr("TLS-пара ещё не загружена")}</strong>
                  <p>{tr("Private key не возвращается в браузер. Чтобы заменить пару, выберите оба файла одновременно.")}</p>
                  {pairReady ? <small>{tr("Действует до:")} {tlsProfileExpiry(existing, locale)}</small> : null}
                </div>
              </aside>
              </>}
              {acme.loadError ? <div className="inline-result inline-result-error form-span" role="alert">{acme.loadError}<button className="button button-tertiary" type="button" onClick={acme.retry}>{tr("Повторить")}</button></div> : null}
              {acme.mode === "acme" ? <p className="field-hint form-span">{tr("Первое подключение сертификата — после Apply. Последующие продления выполняются автоматически.")}</p> : null}
              {editing ? (
                <div className="tls-profile-usage-strip form-span">
                  <small>{tr("Используют")}</small>
                  <span className="tls-profile-uses">
                    {usedByLabels.length
                      ? usedByLabels.map((label) => <span key={label}>{label}</span>)
                      : <em>{tr("Не используется")}</em>}
                  </span>
                </div>
              ) : null}
            </div>
            {error ? <div className="inline-result inline-result-error" role="alert"><span>!</span>{error}</div> : null}
            <div className="tls-profile-footer">
              <Toggle
                name="enabled"
                defaultChecked={existing.enabled !== false}
                tone="state"
                label={tr("Профиль включён")}
                description={tr("Выключенный профиль сохраняется, но не используется подключениями.")}
                title={tr("Связанный профиль можно выключить после переназначения использующих его транспортов.")}
              />
              <div className="modal-actions">
                {editing ? (
                  <button
                    className="button button-danger"
                    type="button"
                    disabled={busy || usedByLabels.length > 0}
                    title={usedByLabels.length ? tr("Сначала выберите другой TLS-профиль во всех связанных транспортах, status / health и клиентской подписке") : tr("Удалить TLS-профиль")}
                    onClick={async () => {
                      if (!deleteArmed) {
                        setDeleteArmed(true);
                        setError(tr("Нажмите «Удалить TLS-профиль» ещё раз. Секреты останутся в хранилище для восстановления."));
                        return;
                      }
                      setBusy(true);
                      setError("");
                      try {
                        await deleteCollectionItem("tls-profiles", profileId!);
                        await onSaved();
                        onClose();
                      } catch (caught) {
                        setError(errorMessage(caught));
                        setBusy(false);
                      }
                    }}
                  >
                    {deleteArmed ? tr("Удалить TLS-профиль") : tr("Подготовить удаление")}
                  </button>
                ) : null}
                {workingId ? <button className="button button-tertiary" type="button" disabled={busy || !pairReady} onClick={() => setExportOpen(true)}>{tr("Экспорт")}</button> : null}
                <button className="button button-tertiary" type="button" onClick={onClose} disabled={busy}>{tr("Отмена")}</button>
                {acme.mode === "acme" && acme.issueAvailable ? <button className="button button-secondary" type="submit" data-issue="true" disabled={busy || ["queued", "running"].includes(String(acme.status.state))}>{tr("Выпустить сертификат")}</button> : null}
                {acme.mode === "local-ca" && localCAPairReady ? <button className="button button-secondary" type="submit" data-generate-local-ca="true" disabled={busy}>{tr("Пересоздать сертификат")}</button> : null}
                <button className="button button-primary" type="submit" disabled={busy || !acme.loaded}>{busy ? tr("Сохраняю…") : tr("Сохранить изменения")}</button>
              </div>
            </div>
          </form>
        )}
      </section>
      {exportOpen && workingId ? <TlsTransferDialog profile={{ id: workingId, name: itemName(existing) }} onClose={() => setExportOpen(false)} onImported={onSaved} /> : null}
    </div>
  );
}
