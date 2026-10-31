document.addEventListener('DOMContentLoaded', () => {
  const body = document.body;
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

  const setMode = (mode) => {
    body.classList.remove('light-mode', 'dark-mode');
    body.classList.add(mode === 'light' ? 'light-mode' : 'dark-mode');
    localStorage.setItem('mode', mode);
    document.querySelectorAll('[data-mode-toggle]').forEach(btn => {
      btn.textContent = mode === 'dark' ? '☀️' : '🌙';
      btn.setAttribute('aria-label', mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
      btn.setAttribute('title', mode === 'dark' ? 'Light mode' : 'Dark mode');
    });
  };

  setMode(localStorage.getItem('mode') || (prefersDark ? 'dark' : 'light'));

  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('[data-mode-toggle]');
    if (!toggle) return;
    const current = body.classList.contains('light-mode') ? 'light' : 'dark';
    setMode(current === 'light' ? 'dark' : 'light');
  });

  const revealItems = document.querySelectorAll('.reveal, .animate-slide-in-up');
  if ('IntersectionObserver' in window && revealItems.length) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    revealItems.forEach((item, index) => {
      item.style.transitionDelay = item.style.getPropertyValue('--delay') || `${Math.min(index * 0.04, 0.35)}s`;
      observer.observe(item);
    });
  } else {
    revealItems.forEach(item => item.classList.add('in-view'));
  }

  document.querySelectorAll('button, .btn-primary, .btn-secondary, .auth-btn, .file-label').forEach(el => {
    el.classList.add('ripple');
  });

  document.addEventListener('click', (event) => {
    const target = event.target.closest('.ripple');
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const dot = document.createElement('span');
    dot.className = 'ripple-dot';
    dot.style.left = `${event.clientX - rect.left}px`;
    dot.style.top = `${event.clientY - rect.top}px`;
    target.appendChild(dot);
    setTimeout(() => dot.remove(), 550);
  });

  document.querySelectorAll('textarea').forEach((textarea) => {
    const autoResize = () => {
      textarea.style.height = 'auto';
      const limit = textarea.classList.contains('comment-input') ? 140 : 240;
      textarea.style.height = `${Math.min(textarea.scrollHeight, limit)}px`;
    };
    autoResize();
    textarea.addEventListener('input', autoResize);
  });

  const postInput = document.getElementById('post-input');
  const charCount = document.getElementById('char-count');
  const previewBtn = document.getElementById('preview-btn');
  const previewBox = document.getElementById('post-preview');
  const imageUpload = document.getElementById('image-upload');
  const selectedFileName = document.getElementById('selected-file-name');

  if (postInput && charCount) {
    const updateCount = () => {
      const length = postInput.value.length;
      charCount.textContent = `${length}/400`;
      charCount.classList.toggle('warning', length > 320);
      if (previewBox) previewBox.classList.remove('show');
    };
    updateCount();
    postInput.addEventListener('input', updateCount);
  }

  if (imageUpload && selectedFileName) {
    imageUpload.addEventListener('change', () => {
      selectedFileName.textContent = imageUpload.files?.[0]?.name || 'No image selected';
    });
  }

  const fallbackSentiment = (text) => {
    const content = text.toLowerCase();
    const positive = ['happy', 'love', 'great', 'awesome', 'wonderful', 'excellent', 'good', 'nice'];
    const negative = ['sad', 'bad', 'hate', 'terrible', 'awful', 'angry', 'annoyed', 'worst'];
    if (positive.some(word => content.includes(word))) return { sentiment: 'positive', score: 0.81 };
    if (negative.some(word => content.includes(word))) return { sentiment: 'negative', score: 0.79 };
    return { sentiment: 'neutral', score: 0.5 };
  };

  const sentimentMeta = {
    positive: { emoji: '😊', label: 'Positive', copy: 'Supportive and uplifting tone detected.' },
    neutral: { emoji: '😐', label: 'Neutral', copy: 'Balanced wording with a steady tone.' },
    negative: { emoji: '😠', label: 'Negative', copy: 'This may feel tense or emotionally sharp.' }
  };

  if (previewBtn && postInput && previewBox) {
    previewBtn.addEventListener('click', async () => {
      const text = postInput.value.trim();
      if (!text) {
        previewBox.innerHTML = '<strong>Write something first.</strong><div class="muted-small" style="margin-top:8px;">Your preview will appear here.</div>';
        previewBox.classList.add('show');
        return;
      }

      previewBox.innerHTML = '<strong>Analyzing post...</strong><div class="muted-small" style="margin-top:8px;">Checking tone and sentiment.</div>';
      previewBox.classList.add('show');

      let result;
      try {
        const res = await fetch('/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text })
        });
        if (!res.ok) throw new Error('Preview failed');
        const data = await res.json();
        result = {
          sentiment: (data.sentiment || 'neutral').toLowerCase(),
          score: Number(data.score ?? 0.5)
        };
      } catch (error) {
        result = fallbackSentiment(text);
      }

      const meta = sentimentMeta[result.sentiment] || sentimentMeta.neutral;
      previewBox.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
          <strong>Predicted sentiment</strong>
          <span class="badge ${result.sentiment}">${meta.emoji} ${meta.label}</span>
        </div>
        <div class="muted-small" style="margin-top:10px;line-height:1.7;">${meta.copy}</div>
        <div class="muted-small" style="margin-top:8px;">Confidence score: ${Number(result.score).toFixed(2)}</div>
      `;
      previewBox.classList.add('show');
    });
  }

  document.addEventListener('click', (event) => {
    const toggle = event.target.closest('.toggle-translation-btn');
    if (!toggle) return;
    const target = document.getElementById(toggle.dataset.target);
    if (!target) return;
    target.classList.toggle('visible');
    toggle.textContent = target.classList.contains('visible') ? 'Hide translation' : 'Show translation';
  });

  let modalResolver = null;
  const modal = document.getElementById('custom-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalMessage = document.getElementById('modal-message');
  const modalConfirm = document.getElementById('modal-confirm-btn');
  const modalCancel = document.getElementById('modal-cancel-btn');

  const closeModal = (value) => {
    if (!modal) return;
    modal.classList.remove('show');
    setTimeout(() => {
      modal.style.display = 'none';
    }, 180);
    if (typeof modalResolver === 'function') modalResolver(value);
    modalResolver = null;
  };

  window.showCustomModal = (title, message, isConfirm = false) => {
    if (!modal) return Promise.resolve(window.confirm ? window.confirm(message) : true);
    modalTitle.textContent = title;
    modalMessage.textContent = message;
    modalCancel.style.display = isConfirm ? 'inline-flex' : 'none';
    modalConfirm.textContent = isConfirm ? 'Confirm' : 'Close';
    modal.style.display = 'flex';
    requestAnimationFrame(() => modal.classList.add('show'));
    return new Promise(resolve => { modalResolver = resolve; });
  };

  if (modalConfirm) modalConfirm.addEventListener('click', () => closeModal(true));
  if (modalCancel) modalCancel.addEventListener('click', () => closeModal(false));
  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal(false);
    });
  }

  const feedContainer = document.querySelector('.center-col') || document.getElementById('feed-list') || document;
  feedContainer.addEventListener('click', async (event) => {
    const deletePostBtn = event.target.closest('.delete-post-btn');
    if (deletePostBtn) {
      const postId = deletePostBtn.dataset.postId;
      const confirmed = await window.showCustomModal('Delete post', 'Are you sure you want to permanently delete this post?', true);
      if (!confirmed) return;
      try {
        const res = await fetch(`/delete_post/${postId}`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          const postEl = document.getElementById(`post-${postId}`);
          if (postEl) {
            postEl.classList.add('animate-fade-out');
            setTimeout(() => postEl.remove(), 280);
          }
        } else {
          window.showCustomModal('Something went wrong', data.error || 'Post deletion failed.');
        }
      } catch (error) {
        window.showCustomModal('Network error', 'Unable to delete the post right now.');
      }
      return;
    }

    const deleteCommentBtn = event.target.closest('.delete-comment-btn');
    if (deleteCommentBtn) {
      const commentId = deleteCommentBtn.dataset.commentId;
      const confirmed = await window.showCustomModal('Delete comment', 'Do you want to remove this comment?', true);
      if (!confirmed) return;
      try {
        const res = await fetch(`/delete_comment/${commentId}`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          const commentEl = document.getElementById(`comment-${commentId}`);
          if (commentEl) {
            commentEl.classList.add('animate-fade-out');
            setTimeout(() => commentEl.remove(), 280);
          }
        } else {
          window.showCustomModal('Something went wrong', data.error || 'Comment deletion failed.');
        }
      } catch (error) {
        window.showCustomModal('Network error', 'Unable to delete the comment right now.');
      }
    }
  });
});
