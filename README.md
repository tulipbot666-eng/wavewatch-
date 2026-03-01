# 🎬 WaveWatch

Watch together, anywhere.

## ✨ Features
- 🔍 Busca de vídeos no YouTube direto no app
- 📋 Fila avançada com thumbnails
- 😂 Reações animadas em tempo real
- 💬 Chat ao vivo com avatars
- 👥 Perfil de usuário com avatar emoji
- 🕘 Histórico de vídeos da sala
- ⚡ Sincronização via WebSocket (play/pause/seek em tempo real)
- Suporte: YouTube, Vimeo, Twitch, MP4, WebM, arquivo local

---

## 🚀 Deploy no Railway (grátis)

1. Crie uma conta em **https://railway.app** (grátis, sem cartão)
2. Clique em **"New Project" → "Deploy from GitHub"**
   - OU clique em **"New Project" → "Empty Project"** → arraste a pasta `wavewatch`
3. O Railway detecta automaticamente o Node.js e faz o deploy
4. Clique em **"Generate Domain"** para obter seu link público
5. Pronto! Compartilhe o link com seus amigos 🎉

## 🖥️ Rodar localmente

```bash
npm install
npm start
```

Acesse: http://localhost:3000

---

## ⚙️ Variáveis de ambiente (opcionais)

| Variável | Descrição | Padrão |
|----------|-----------|--------|
| `PORT` | Porta do servidor | `3000` |

---

## 📁 Estrutura

```
wavewatch/
├── server.js       ← Backend Node.js + WebSocket
├── package.json    ← Dependências
├── README.md
└── public/
    └── index.html  ← Frontend completo
```
