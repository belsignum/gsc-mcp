# syntax=docker/dockerfile:1
# Basis-Images per Digest festgelegt; Dependabot schlägt neue Digests als PR vor (regelmäßiger Neubau).
FROM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev && mkdir /out && cp -r package.json node_modules dist /out/
# Verzeichnisse für die Volumes: Besitzer nonroot (65532), Rechte 0700. Neue Volumes übernehmen das.
RUN mkdir -p /volumes/config /volumes/data/audit /volumes/keys

# Laufzeit ohne Shell und Paketmanager
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:675c532423b908f9e56f9d60a4e62309b63cd2a3175acb90a46b96f7ee68e121
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    GSC_CONFIG=/config/tokens.yaml \
    GSC_KEY_DIR=/run/secrets/gsc \
    GSC_AUDIT_DIR=/data/audit
# Der Code gehört root und ist für den Laufzeitnutzer nur lesbar. Kein WORKDIR vor dem COPY:
# das distroless-Image läuft als nonroot und würde /app sonst diesem Nutzer geben.
COPY --from=build --chown=0:0 /out /app
COPY --from=build --chown=65532:65532 --chmod=700 /volumes/config /config
COPY --from=build --chown=65532:65532 --chmod=700 /volumes/data /data
COPY --from=build --chown=65532:65532 --chmod=700 /volumes/keys /run/secrets/gsc
WORKDIR /app
USER 65532:65532
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "--permission", "--allow-fs-read=/app/dist/", "/app/dist/healthcheck.js"]
# Node Permission Model: lesen nur Code, Freigaben, Schlüssel und Audit-Log; schreiben nur das Audit-Log;
# keine Kindprozesse, Worker, Addons, WASI oder Inspector; kein eval. Eine zusätzliche Hürde, keine Sicherheitsgrenze.
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["--permission", "--disallow-code-generation-from-strings", "--allow-fs-read=/app/", "--allow-fs-read=/config/", "--allow-fs-read=/run/secrets/gsc/", "--allow-fs-read=/data/audit/", "--allow-fs-write=/data/audit/", "/app/dist/http.js"]
