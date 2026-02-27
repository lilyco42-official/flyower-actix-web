const feed = document.getElementById('feed');

let page = 1;
let loading = false;

async function loadFeed() {
  if (loading) return;
  loading = true;

  const data = await request(`/images?page=${page}&sort=latest`);
  data.images.forEach(renderCard);

  page++;
  loading = false;
}

function renderCard(img) {
  const div = document.createElement('div');
  div.className = 'card';

  div.innerHTML = `
    <img src="/uploads/${img.filename}" />
    <div class="info">
      ❤️ ${img.like_count} ⭐ ${img.collect_count}
    </div>
  `;

  feed.appendChild(div);
}

window.onscroll = () => {
  if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 300) {
    loadFeed();
  }
};

loadFeed();
searchInput.onchange = async () => {
  feed.innerHTML = '';
  page = 1;

  const q = searchInput.value;

  const data = await request(`/images?q=${q}`);
  data.images.forEach(renderCard);
};