if('loading' in HTMLImageElement.prototype){
  const images = document.querySelectorAll('img[loading="lazy"]');
  images.forEach(img => {
    img.src = img.getAttribute('lz-src');
    img.removeAttribute('lz-src');
  });
}

