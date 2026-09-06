# LifeDB

LifeDBは、個人のためのローカルファーストでエージェント中立、復旧可能な記憶基盤です。Canon（カノン）は所有者が承認した現在のモデルです。Evidence（証跡）は観測または取得した内容を記録するものであり、真実としてのラベルは付けません。データベース、埋め込み、コンテナ、実効ビュー、Context Pack（コンテキストパック）は使い捨ての投影です。

このリポジトリは、LifeDB v0.2の実行可能な仕様とリファレンス実装です。CanonバンドルはOKF v0.2を対象とし、パス非依存のUUIDv7アイデンティティと`x-lifedb`配下の型付きClaim（主張）来歴を追加しています。互換性の基準は[OKF v0.2仕様](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)です。

## 4つのストア

| ストア | 目的 | 権威 | 削除可否 |
| --- | --- | --- | --- |
| `canon/` | 承認済みの最新セマンティックモデル | 現在のセマンティック状態 | 所有者が明示的に承認した操作でのみ可能 |
| `evidence/` | 不変の取得記録と追記専用イベント | LifeDBが記録した内容とそのライフサイクル | 通常は追記専用、所有者による消去が例外 |
| `objects/` | 生データ、表現物、Canonスナップショットのバイト列 | 存在する間のバイト同一性 | ポリシーと依存関係による |
| `runtime/` | SQLiteインデックス、実効ビュー、キャッシュ、Context Pack（コンテキストパック） | 権威を持たない | 常に可能 |

現在のペイロードの有無と表現物は、封印済み取得記録と順序付きの不変ライフサイクルイベントから投影します。ペイロードは、観測の包みを残したまま退避できます。SHA-256はバイト列の変化を検出し、重複排除に使います。情報源の認証や主張の証明には使いません。

## v0.2リファレンスの実装内容

- UUIDv7の保管庫アイデンティティとセマンティックアイデンティティを利用します。
- schema 0.2を用いた、不可分で完全性を備えたEvidence（証跡）取得記録を作成します。
- ソーススコープの`external_id`べき等性を保ちます。キーは`(source.kind, source.uri, source.account, source.device, source.external_id)`です。従来の`source.metadata.account`や`device`の値はソース外枠に繰り上げます。
- SHA-256によるObject Storeの重複排除を行います。
- URIを必須とし原本バイトを一切保存しない`reference-only`取得に対応します。
- `previous_event`連結を持つ保管庫全体の追記専用イベント連番を維持します。
- 表現物とペイロードライフサイクルのための実効Evidence（証跡）投影を提供します。
- 型付きClaim（主張）のEvidence（証跡）要件に対応します。`raw`、`representation:<role>`、`record-only`です。
- 手動Candidate（候補）の作成、確認、却下、昇格を明示的に行います。
- 準備済み・確定済みのCanonスナップショットトランザクションと補償ロールバックを実行します。
- CanonとEvidence（証跡）の検証、使い捨て語彙インデックスの再構築を行います。
- `concepts`、`claims`、`claim_evidence`、`claim_edges`向けSQLite投影を提供します（グラフ状データは実体化しますが、グラフ問い合わせやランキングAPIは公開しません）。
- ダーティインデックスとdurable/indexedの順序ウォーターマークを管理します。
- 文字数予算付きContext Pack（コンテキストパック）を提供します。Core、ヒューリスティックなContinuity、語彙的なRelevant検索、信頼できない内容の区切りを含みます。
- 対象のrawペイロードに対する明示的な保持プレビュー、厳密確認付き適用、中断適用からの回復を提供します（手動CLI操作のみ）。
- HTTP向けBearer認証とサーバー側感度上限を提供します。
- サーバー側の感度上限・下限の強制と、ポリシー範囲内のContext予算を適用します。
- Dockerバインドマウント配置とruntime削除からの回復試験に対応します。

実行可能な境界は意図的に有限です。HTTPとCLIのraw入力は64 MiBまで、durableレコードは16 MiBまで、Canonとインデックス対象テキストは8 MiBまで、ContextとEvidence（証跡）展開は1,000,000文字まで、検索クエリは4,096文字まで、検索結果は100件までです。フロントマター、マッピング、ポリシー、ソースメタデータは各1 MiBまで、イベントデータは4 MiBまでです。これらは資源の上限であり、処理能力の保証ではありません。イベント追記とソースべき等性の照合はdurableレコード集合に対するO(N)であり、v0.2リファレンスは単一のdurableライターを使います。

## 意図的に実装していない項目

現在のリファレンスソフトウェアは以下を実装していません。

- 自動AI抽出、Candidate（候補）作成、昇格、バックグラウンド照合。
- オブジェクトの自動退避や定期的な保持適用。
- 所有者承認による消去のプレビュー・適用。
- 汎用の自動エージェントpreflight/postflightフック。
- MCP。
- ベクトル、グラフランク付け、埋め込み、学習型リランク検索。
- ブラウザ、メール、カレンダー、ActivityWatch、スクリーンショット、音声、その他外部コレクター。
- OCR、キャプション生成、書き起こし、その他表現物の生成処理。
- 複数ライターや複数デバイス間の同期。
- アプリケーション層のオブジェクト暗号化やデジタル署名。

通常の保持では、厳密で永続化済みプレビューにより選ばれたrawのObject Storeバイト列のみ削除できます。封印済みEvidence（証跡）の包みは消去せず、自動的な定期実行も行いません。所有者による消去は仕様化済みですが未実装です。暗号化ホストストレージと暗号化バックアップは配置側の責務です。durable形式が将来分を予約しているという理由だけで、未実装の機能をうたってはなりません。

## CLIクイックスタート

独立したPython環境に導入し、実際の保管庫はソースリポジトリの外に置きます。

```sh
python -m pip install .
export LIFEDB_VAULT=/absolute/path/to/lifedb-vault
lifedb init
printf '%s' 'LifeDB remains reconstructable from durable files.' \
  | lifedb ingest - --media-type text/plain --filename memory.txt
lifedb validate
lifedb rebuild
lifedb context 'What must remain reconstructable?' --markdown
```

CLI呼び出しは現在のOSユーザーとして実行され、HTTP認証層を経由しません。ファイルシステム権限と暗号化ストレージで保管庫を保護します。

明示的で有用なワークフローは次のとおりです。最初の例は、直近の会話EvidenceにContinuity経路指定ラベルを付けて取り込み、続きの問合せで辿れるようにします。次の例は、不変の表現物イベントを作成します。最後の例は、適格なrawペイロード退避をプレビューし、厳密確認付きで適用して中断時の回復まで行います。適用の権限を持つのは永続化済みの計画文書のみであり、画面表示は情報提供にすぎません。返された識別子と確認値は正確に写し取り、適用は永続化計画を再検証するため、durable状態が変わっていれば失敗します。

```sh
# Associate recent conversation Evidence with Continuity routing labels.
printf '%s' 'Continue the migration after validation.' \
  | lifedb ingest - --media-type text/plain --kind conversation \
      --source-metadata '{"session":"session-42","workspace":"/srv/project"}'
lifedb context 'What remains open?' --session session-42 \
  --workspace /srv/project --markdown

# Create an immutable representation event.
lifedb evidence add-representation 019d0000-0000-7000-8000-000000000001 ocr.txt \
  --role ocr --media-type text/plain --actor process:ocr \
  --producer-version 1.0

# Preview eligible raw-payload eviction. The persisted plan file under
# runtime/retention/ is the apply authority; displayed output is
# informational only. Copy the returned id and confirmation
# exactly; apply revalidates the persisted plan and fails if durable state changed.
lifedb retention preview
lifedb retention apply 019d0000-0000-7000-8000-000000000002 \
  --confirm 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --actor owner:local
lifedb retention recover
```

上のUUIDとダイジェストは仮の値です。新規保管庫では手動取り込みの既定が`durable`であり、通常の退避対象から意図的に除外します。`grace`または`derivative-only`でポリシー適合の取得のみ候補に現れます。

## Docker

```sh
cp .env.example .env
mkdir -p ./vault
docker compose run --rm lifedb init
docker compose up -d --build lifedb
curl http://127.0.0.1:7331/health
```

既定の配置はホスト保管庫をバインドマウントし、localhostにのみ公開します。実データでは`LIFEDB_VAULT`に絶対パスでバックアップ済みホストパスを設定します。無名Dockerボリュームだけをdurable複製にしてはなりません。

## 認証付きHTTP

強固な`LIFEDB_API_TOKEN`をサービス環境または外部シークレット機構に設定します。保管庫に入れたりコミットしたりしないでください。`/v1/*`への全要求にBearerトークンが必要であり、`/health`のみ認証不要です。設定済みトークンは空白を含まない32以上4096以下のUTF-8バイトとし、前後の空白も含め空白は一切使えません。不正な設定値はサーバーが待受ソケットを開く前に失敗します。未設定または空の場合、HTTP認証は未構成のままです。`/health`は利用可能ですが、`/v1/*`要求はフェールクローズします。

`LIFEDB_SENSITIVITY_CEILING`はサーバーの最大値を定め、既定は`personal`です。要求側はより低い上限を求められますが、引き上げはできません。`LIFEDB_INGEST_SENSITIVITY_FLOOR`はHTTP取得に付与する最小ラベルを定めます。呼び出し側はラベルを引き上げられますが、引き下げはできません。Context予算も検証済みdurableコンテキストポリシーで制限します。

```sh
curl -X POST http://127.0.0.1:7331/v1/context \
  -H "Authorization: Bearer ${LIFEDB_API_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "What are the storage invariants?",
    "budget_chars": 12000,
    "core_chars": 4000,
    "continuity_chars": 2000,
    "relevant_chars": 6000
  }'
```

サーバーは要求された感度と文字数予算を自プロファイルに収めます。Context出力は`{durable_sequence, indexed_sequence, dirty}`を報告し、取得メモリをエスケープ済みuntrusted-data区切りで囲みます。

localhostはそれだけでは認可境界になりません。リファレンスサーバーは所有者Bearerトークンを1つ持ち、その中で操作範囲を分けません。外部公開にはさらにTLS、リバースプロキシ、宛先ポリシー、レートと割当管理、空き容量監視、明示的なセキュリティレビューが必要です。リファレンスはソース別割当、要求レート、空き容量しきい値を強制しません。

## Claimと保持される裏付け

v0.2のClaim（主張）は必要な最小Evidence（証跡）資料を指定します。

```yaml
evidence:
  - id: 019d1255-7d6a-7e43-92bd-0f137f516006
    requires: raw
  - id: 019d1255-7d6a-7e43-92bd-0f137f516007
    requires: representation:ocr
  - id: 019d1255-7d6a-7e43-92bd-0f137f516008
    requires: record-only
```

素のv0.1 Evidence（証跡）UUIDは保守的に`raw`として読みます。新規v0.2書き込みは明示マッピングを使います。したがってCanon引用はrawのウェブ取得や受動取得ペイロードのすべてを自動固定しませんが、真のraw依存は黙って退避されません。

## 手動Candidateワークフロー

取り込みはEvidence（証跡）を作り、Canon（カノン）は作りません。手動Candidate（候補）は対象Canon文書向けに検証済みClaim（主張）を提案します。明示的な昇格では、セマンティック参照とEvidence（証跡）参照、感度、有効性、置換を検証してから、以下でCanon（カノン）に書き込みます。

1. durableの前後スナップショット。
2. `canon.change-prepared`。
3. 不可分compare-and-swap公開。
4. `canon.change-committed`。

失敗時は前スナップショットに戻し、中止トランザクションを記録します。ロールバックは現在バイト列を検証し、`canon.rollback-prepared/committed`を作ります。元履歴は消しません。v0.2に自動AI昇格はありません。

## 復旧の不変条件

`runtime/`の削除により、承認済み知識や観測履歴を失ってはなりません。先にLifeDBサーバーを止め、対象の初期化済み保管庫に限定した保護付きコマンドを使います（広範囲、シンボリックリンク、未初期化の対象は拒否します）。

```sh
docker compose down
docker compose run --rm lifedb runtime reset --confirm DELETE-RUNTIME
docker compose run --rm lifedb rebuild
docker compose run --rm lifedb validate
```

設定済み保管庫パスを確定してから実行します。復旧では取得記録とイベントの完全性、イベント順序、保持オブジェクト、Canonスナップショット、型付きEvidence（証跡）要件、再構築ウォーターマークを検証します。

durableバックアップ一式は`vault.json`、`canon/`、`evidence/`、`objects/`、`policies/`、`schemas/`、`migrations/`です。保持トランザクションの準備済みまたは実行中は`quarantine/`を含めます。それ以外は権威ストアではなく一時領域扱いです。`runtime/`は使い捨てのためバックアップ不要です。バックアップは宣言済みdurable順序で一貫させます。GitだけではLifeDBバックアップになりません。

## 個人データと所有者による消去

実保管庫では暗号化ホストストレージ、暗号化オフサイトバックアップ、制限付きファイル権限、鍵の分離管理を使います。保管庫、認証トークン、パスワード、秘密鍵、資格情報をコミットしないでください。

通常レコードは追記専用ですが、所有者承認の消去が優先します。設計上、取得記録、イベント、オブジェクト、表現物、Canonスナップショット、runtime複製にわたる完全なプレビューと厳密確認が必要です。LifeDB自体はオフラインや事業者管理バックアップを削除できません。在庫管理、有効期限、消去済みデータの復元防止は配置運用者の責務です。

v0.2リファレンスは所有者消去のプレビューも適用も実装していません。通常の`lifedb retention apply`を代用にしないでください。対象rawペイロードオブジェクトのみ除去し、取得記録とイベント履歴は意図的に残します。

## 資料

- [durable形式とCanon仕様](SPEC.md)
- [思想とv0.2の境界](docs/philosophy.md)
- [脅威モデル](docs/threat-model.md)
- [コンテキストプロトコル](docs/context-protocol.md)
- [保持ポリシー](docs/retention.md)
- [災害復旧](docs/disaster-recovery.md)
- [検証記録](docs/verification.md) (v0.2検証・リリースゲート記録)
- [ADR 0001: durableファイルと使い捨てruntime](docs/decisions/0001-durable-files-disposable-runtime.md)
- [ADR 0002: 追記専用ライフサイクルイベントとCanonトランザクション](docs/decisions/0002-append-only-lifecycle-events.md)

## 適合ステータス

バージョン0.2では、実行コアをdurable取得・イベント、明示的な手動Canon変更、認可付き語彙Context、復旧に絞ります。リポジトリの試験は、実行した経路の証拠であり、外部Docker、バックアップ、TLS、モデル事業者、将来コレクターの動作を検証した主張ではありません。

MCP、ベクトル、グラフランク付け検索、コレクター、表現物生成、自動preflight/postflight統合、自動AI照合はv0.2適合の対象外と明示します。
